/*
 * Copyright (c) 2026 Alexandre Bailon <abailon@baylibre.com>
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <errno.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/random/random.h>
#include <zephyr/sys/byteorder.h>

#include <lora_star/lora_star.h>
#include <lora_star/mac.h>
#include <lora_star/crypto.h>
#include <lora_star/coord.h>
#include <lora_star/rejoin.h>
#ifdef CONFIG_LORA_STAR_NODE
#include <zephyr/drivers/hwinfo.h>
#endif

#include "storage.h"

LOG_MODULE_REGISTER(ls_rejoin, CONFIG_LORA_STAR_LOG_LEVEL);

/*
 * Everything below is role-specific; a build with neither role has no use
 * for this file's contents (mirrors mac.c/lora_star.c having nothing
 * meaningful to do without a role either), so guard the lot to avoid an
 * unused-function warning on the shared helper below.
 */
#if defined(CONFIG_LORA_STAR_COORDINATOR) || defined(CONFIG_LORA_STAR_NODE)

/* --------------------------------------------------------------------------
 * Rejoin-specific crypto helpers
 * -------------------------------------------------------------------------- */

/*
 * Derive the 16-byte session key using HKDF-SHA256 (RFC 5869).
 *
 * Both sides already hold the network key, so unlike pairing this needs no
 * ECDH exchange: the network key itself is the HKDF secret. Both nonces
 * (one contributed by each side) go into the salt, so every rejoin derives
 * a different session key even though the underlying network key never
 * changes — that freshness is what makes replaying an old session's traffic
 * fail MIC verification under the new key.
 */
static int rejoin_hkdf_session_key(const uint8_t network_key[LS_NETWORK_KEY_SIZE],
				   const uint8_t dev_eui[LS_DEV_EUI_SIZE],
				   const uint8_t node_nonce[LS_REJOIN_NONCE_SIZE],
				   const uint8_t coord_nonce[LS_REJOIN_NONCE_SIZE],
				   uint8_t key[LS_NETWORK_KEY_SIZE])
{
	uint8_t salt[LS_DEV_EUI_SIZE + LS_REJOIN_NONCE_SIZE + LS_REJOIN_NONCE_SIZE];
	const uint8_t info[] = "lora_star_session_v1";

	memcpy(salt, dev_eui, LS_DEV_EUI_SIZE);
	memcpy(salt + LS_DEV_EUI_SIZE, node_nonce, LS_REJOIN_NONCE_SIZE);
	memcpy(salt + LS_DEV_EUI_SIZE + LS_REJOIN_NONCE_SIZE, coord_nonce, LS_REJOIN_NONCE_SIZE);

	return ls_crypto_hkdf(network_key, LS_NETWORK_KEY_SIZE, salt, sizeof(salt),
			      info, sizeof(info) - 1, key);
}

/* --------------------------------------------------------------------------
 * Coordinator side
 * -------------------------------------------------------------------------- */

#ifdef CONFIG_LORA_STAR_COORDINATOR

static int rejoin_req_cb(struct ls_ctx *ctx, struct ls_frame *frame, void *user_data)
{
	uint8_t *payload;
	size_t payload_len;
	const struct ls_rejoin_req_payload *rq;
	uint8_t coord_nonce[LS_REJOIN_NONCE_SIZE];
	uint8_t session_key[LS_NETWORK_KEY_SIZE];
	struct ls_rejoin_accept_payload ra;
	uint16_t short_addr;
	bool is_repair;
	int ret;

	ARG_UNUSED(user_data);

	ls_frame_get_payload(frame, &payload, &payload_len);
	if (payload_len != LS_REJOIN_REQ_PAYLOAD_SIZE) {
		return 0;
	}
	rq = (const struct ls_rejoin_req_payload *)payload;

	/*
	 * Signed with the long-term network key: this confirms the sender
	 * genuinely holds it before we spend a nonce and an HKDF derivation
	 * on it. No RSSI gating here, unlike pairing — trust comes from key
	 * possession, not proximity.
	 */
	ret = ls_frame_check_signature(frame, ctx->network_key);
	if (ret < 0) {
		LOG_WRN("REJOIN_REQ MIC mismatch");
		return 0;
	}

	/*
	 * Always resolve by DevEUI (LS_BCAST_ADDR forces that path in
	 * ls_coord_add_node()) — a returning node's address comes from the
	 * node table, not from whatever it happened to put in SRC.
	 */
	short_addr = ls_coord_add_node(ctx, rq->dev_eui, LS_BCAST_ADDR, &is_repair);
	if (short_addr == 0) {
		return 0;
	}

	ret = sys_csrand_get(coord_nonce, sizeof(coord_nonce));
	if (ret < 0) {
		LOG_ERR("RNG failed");
		return 0;
	}

	ret = rejoin_hkdf_session_key(ctx->network_key, rq->dev_eui, rq->node_nonce,
				      coord_nonce, session_key);
	if (ret < 0) {
		LOG_ERR("Session key derivation failed");
		return 0;
	}

	ls_coord_set_session(short_addr, session_key);

	memcpy(ra.coord_nonce, coord_nonce, LS_REJOIN_NONCE_SIZE);
	sys_put_le16(short_addr, ra.short_addr);

	/*
	 * Sign with the freshly derived session key itself — the node
	 * verifying this MIC with its own independently-derived copy of that
	 * key is mutual confirmation, no third message needed.
	 */
	ret = ls_send_async(ctx, LS_TYPE_REJOIN_ACCEPT,
			    LS_COORD_ADDR, LS_BCAST_ADDR, 0,
			    (const uint8_t *)&ra, LS_REJOIN_ACCEPT_PAYLOAD_SIZE,
			    session_key,
			    false, 0, 0, 0,
			    NULL, NULL);
	memset(session_key, 0, sizeof(session_key));
	if (ret < 0) {
		LOG_ERR("REJOIN_ACCEPT enqueue failed");
		return 0;
	}

	LOG_INF("Node 0x%04x %s", short_addr, is_repair ? "rejoined" : "registered");

	return -1;
}

/*
 * Repeats the coordinator's boot HELLO a few times (best-effort — it's a
 * broadcast with no ACK, and only nodes that happen to be listening right
 * now will ever see it). CONFIG_LORA_STAR_COORD_HELLO_COUNT/_INTERVAL_MS
 * control the repeat count and spacing.
 */
static struct {
	struct k_work_delayable work;
	struct ls_ctx          *ctx;
	int                      remaining;
} hello_state;

static void hello_work_handler(struct k_work *work)
{
	ARG_UNUSED(work);

	if (hello_state.remaining <= 0) {
		return;
	}

	(void)ls_send_async(hello_state.ctx, LS_TYPE_COORD_HELLO,
			    LS_COORD_ADDR, LS_BCAST_ADDR, 0,
			    NULL, 0, hello_state.ctx->network_key,
			    false, 0, 0, 0, NULL, NULL);

	hello_state.remaining--;
	if (hello_state.remaining > 0) {
		k_work_schedule(&hello_state.work,
				K_MSEC(CONFIG_LORA_STAR_COORD_HELLO_INTERVAL_MS));
	}
}

int ls_rejoin_coord_init(struct ls_ctx *ctx)
{
	static const struct ls_frame_filter rq_filter = {
		.type = LS_TYPE_REJOIN_REQ,
		.src  = LS_BCAST_ADDR,
		.dst  = LS_BCAST_ADDR,
	};

	if (!ls_register_frame_cb(ctx, &rq_filter, rejoin_req_cb, NULL)) {
		return -ENOMEM;
	}

	hello_state.ctx       = ctx;
	hello_state.remaining = CONFIG_LORA_STAR_COORD_HELLO_COUNT;
	k_work_init_delayable(&hello_state.work, hello_work_handler);
	k_work_schedule(&hello_state.work, K_NO_WAIT);

	return 0;
}

#endif /* CONFIG_LORA_STAR_COORDINATOR */

/* --------------------------------------------------------------------------
 * Node side
 * -------------------------------------------------------------------------- */

#ifdef CONFIG_LORA_STAR_NODE

/*
 * Single static instance: only one rejoin handshake can ever be in flight
 * for a device (mirrors ls_coord_get()'s singleton pattern rather than
 * pairing's app-owned context struct — there is nothing for an application
 * to configure here beyond the DevEUI, so no reason to make it own state).
 */
struct rejoin_node_state {
	uint8_t                  dev_eui[LS_DEV_EUI_SIZE];
	uint8_t                  node_nonce[LS_REJOIN_NONCE_SIZE];
	int                      result;
	struct ls_frame_handler *accept_hdl;
	ls_rejoin_done_cb        done_cb;
	void                    *done_user_data;
	struct ls_ctx           *ctx;
};

static struct rejoin_node_state node_state;

/*
 * Called by the LoRa Star thread when a REJOIN_ACCEPT arrives. Derives the
 * session key first (needs coord_nonce out of the payload), then verifies
 * the frame MIC with it — a mismatch means this wasn't a reply to us (wrong
 * coordinator, stale nonce) and the thread should keep waiting.
 */
static int rejoin_accept_cb(struct ls_ctx *ctx, struct ls_frame *frame, void *user_data)
{
	struct rejoin_node_state *st = user_data;
	uint8_t *payload;
	size_t payload_len;
	const struct ls_rejoin_accept_payload *ra;
	uint8_t session_key[LS_NETWORK_KEY_SIZE];
	uint16_t short_addr;
	int ret;

	ls_frame_get_payload(frame, &payload, &payload_len);
	if (ls_frame_get_src(frame) != LS_COORD_ADDR ||
	    payload_len != LS_REJOIN_ACCEPT_PAYLOAD_SIZE) {
		return 0;
	}
	ra = (const struct ls_rejoin_accept_payload *)payload;

	ret = rejoin_hkdf_session_key(ctx->network_key, st->dev_eui, st->node_nonce,
				      ra->coord_nonce, session_key);
	if (ret < 0) {
		LOG_ERR("Session key derivation failed");
		st->result = ret;
		return -1;
	}

	ret = ls_frame_check_signature(frame, session_key);
	if (ret < 0) {
		LOG_WRN("REJOIN_ACCEPT MIC mismatch — ignoring frame");
		memset(session_key, 0, sizeof(session_key));
		return 0;
	}

	short_addr = sys_get_le16(ra->short_addr);

	memcpy(ctx->_session_key, session_key, LS_NETWORK_KEY_SIZE);
	memset(session_key, 0, sizeof(session_key));
	ctx->_session_active  = true;
	ctx->fcnt             = 0;
	ctx->_session_rx_fcnt = 0;

	if (short_addr != ctx->own_addr) {
		ls_set_own_addr(ctx, short_addr);
	}
	ls_storage_save_all(ctx);

	LOG_INF("Session established — ShortAddr 0x%04x", short_addr);
	st->result = 0;
	return -1;
}

static void rejoin_done_cb(int ret, void *user_data)
{
	struct rejoin_node_state *st = user_data;
	int result = (ret == 0) ? st->result : ret;

	ls_unregister_frame_cb(st->ctx, st->accept_hdl);
	st->accept_hdl = NULL;

	if (st->done_cb) {
		st->done_cb(st->ctx, result, st->done_user_data);
	}
}

int ls_rejoin_start(struct ls_ctx *ctx, const uint8_t dev_eui[LS_DEV_EUI_SIZE],
		    ls_rejoin_done_cb done_cb, void *user_data)
{
	static const struct ls_frame_filter ra_filter = {
		.type = LS_TYPE_REJOIN_ACCEPT,
		.src  = LS_COORD_ADDR,
		.dst  = LS_BCAST_ADDR,
	};
	struct rejoin_node_state *st = &node_state;
	struct ls_rejoin_req_payload rq;
	uint16_t src;
	uint32_t window_ms;
	int ret;

	if (ctx == NULL || dev_eui == NULL) {
		return -EINVAL;
	}

	/*
	 * A rejoin is already in flight (accept_hdl is only non-NULL between
	 * here and rejoin_done_cb). Without this guard a second trigger — e.g.
	 * SESSION_UNKNOWN arriving while the boot auto-rejoin is still
	 * outstanding — would overwrite node_state out from under the first
	 * attempt and leak a frame_cb registry slot.
	 */
	if (st->accept_hdl != NULL) {
		return -EBUSY;
	}

	st->ctx            = ctx;
	st->result         = -ETIMEDOUT;
	st->done_cb        = done_cb;
	st->done_user_data = user_data;
	memcpy(st->dev_eui, dev_eui, LS_DEV_EUI_SIZE);

	ret = sys_csrand_get(st->node_nonce, sizeof(st->node_nonce));
	if (ret < 0) {
		return ret;
	}

	st->accept_hdl = ls_register_frame_cb(ctx, &ra_filter, rejoin_accept_cb, st);
	if (!st->accept_hdl) {
		return -ENOMEM;
	}

	memcpy(rq.dev_eui, dev_eui, LS_DEV_EUI_SIZE);
	memcpy(rq.node_nonce, st->node_nonce, LS_REJOIN_NONCE_SIZE);

	/* LS_BCAST_ADDR if we don't have an address yet; the coordinator
	 * resolves us by DevEUI regardless (see rejoin_req_cb()).
	 */
	src = (ctx->own_addr != LS_COORD_ADDR) ? ctx->own_addr : LS_BCAST_ADDR;

	window_ms = ls_mac_airtime_ms(ctx, LS_FRAME_SIZE(LS_REJOIN_ACCEPT_PAYLOAD_SIZE))
		  + CONFIG_LORA_STAR_ACK_GUARD_MS;

	ret = ls_send_async(ctx, LS_TYPE_REJOIN_REQ,
			    src, LS_BCAST_ADDR, 0,
			    (const uint8_t *)&rq, LS_REJOIN_REQ_PAYLOAD_SIZE,
			    ctx->network_key,
			    true, LS_TYPE_REJOIN_ACCEPT, LS_COORD_ADDR,
			    window_ms, rejoin_done_cb, st);
	if (ret == 0) {
		return 0;
	}

	ls_unregister_frame_cb(ctx, st->accept_hdl);
	st->accept_hdl = NULL;
	return ret;
}

/*
 * Shared reaction for both session-recovery notices: verify the network-key
 * MIC, then kick off a fresh rejoin. SESSION_UNKNOWN also checks DST since
 * it is addressed to a specific node (read live off ctx->own_addr rather
 * than baked into the registered filter, since that address can change
 * across a re-pair); COORD_HELLO is a genuine broadcast so any node holding
 * the network key reacts to it.
 */
static int recovery_notice_cb(struct ls_ctx *ctx, struct ls_frame *frame, void *user_data)
{
	uint8_t dev_eui[LS_DEV_EUI_SIZE];
	uint8_t type;
	int ret;

	ARG_UNUSED(user_data);

	type = ls_frame_get_type(frame);

	if (ls_frame_get_src(frame) != LS_COORD_ADDR) {
		return 0;
	}
	if (type == LS_TYPE_SESSION_UNKNOWN && ls_frame_get_dst(frame) != ctx->own_addr) {
		return 0;
	}

	ret = ls_frame_check_signature(frame, ctx->network_key);
	if (ret < 0) {
		LOG_WRN("%s MIC mismatch — ignoring",
			type == LS_TYPE_COORD_HELLO ? "COORD_HELLO" : "SESSION_UNKNOWN");
		return 0;
	}

	LOG_INF("%s received — rejoining",
		type == LS_TYPE_COORD_HELLO ? "COORD_HELLO" : "SESSION_UNKNOWN");

	hwinfo_get_device_id(dev_eui, sizeof(dev_eui));
	ret = ls_rejoin_start(ctx, dev_eui, NULL, NULL);
	if (ret < 0 && ret != -EBUSY) {
		LOG_WRN("Rejoin failed to start: %d", ret);
	}

	return -1;
}

int ls_rejoin_node_init(struct ls_ctx *ctx)
{
	static const struct ls_frame_filter session_unknown_filter = {
		.type = LS_TYPE_SESSION_UNKNOWN,
		.src  = LS_COORD_ADDR,
		.dst  = LS_BCAST_ADDR,
	};
	static const struct ls_frame_filter coord_hello_filter = {
		.type = LS_TYPE_COORD_HELLO,
		.src  = LS_COORD_ADDR,
		.dst  = LS_BCAST_ADDR,
	};

	if (!ls_register_frame_cb(ctx, &session_unknown_filter, recovery_notice_cb, NULL)) {
		return -ENOMEM;
	}
	if (!ls_register_frame_cb(ctx, &coord_hello_filter, recovery_notice_cb, NULL)) {
		return -ENOMEM;
	}
	return 0;
}

#endif /* CONFIG_LORA_STAR_NODE */

#endif /* CONFIG_LORA_STAR_COORDINATOR || CONFIG_LORA_STAR_NODE */
