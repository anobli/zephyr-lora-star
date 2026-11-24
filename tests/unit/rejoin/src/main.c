/*
 * Copyright (c) 2026 Alexandre Bailon <abailon@baylibre.com>
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <errno.h>

#include <zephyr/ztest.h>
#include <zephyr/drivers/lora.h>
#include "ls_fake_radio.h"
#include <zephyr/sys/byteorder.h>

#include <lora_star/lora_star.h>
#include <lora_star/mac.h>
#include <lora_star/frame.h>
#include <lora_star/crypto.h>
#include <lora_star/coord.h>
#include <lora_star/rejoin.h>

/*
 * Coordinator-side only, mirroring tests/unit/pairing's scope: exercises
 * rejoin_req_cb() (subsys/lora_star/rejoin.c) by injecting REJOIN_REQ frames
 * built the same way a real node would build them, and checking the
 * REJOIN_ACCEPT reply plus the resulting node-table/session state.
 */

/* --------------------------------------------------------------------------
 * Shared test vectors
 * -------------------------------------------------------------------------- */

static const uint8_t test_network_key[LS_NETWORK_KEY_SIZE] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
};

/* --------------------------------------------------------------------------
 * Helpers
 * -------------------------------------------------------------------------- */

/*
 * Encode a complete, MIC-signed REJOIN_REQ frame into buf[]. Unlike JOIN_REQ,
 * this is signed directly with the network key — no per-frame derived key,
 * since both sides already share the network key by the time rejoin runs.
 */
static void build_rejoin_req(uint8_t *buf, size_t buf_size,
			     const uint8_t dev_eui[LS_DEV_EUI_SIZE],
			     const uint8_t node_nonce[LS_REJOIN_NONCE_SIZE],
			     const uint8_t network_key[LS_NETWORK_KEY_SIZE])
{
	struct ls_rejoin_req_payload rq;
	struct ls_frame frame;
	int ret;

	zassert_true(buf_size >= LS_FRAME_SIZE(LS_REJOIN_REQ_PAYLOAD_SIZE),
		     "output buffer too small");

	memcpy(rq.dev_eui, dev_eui, LS_DEV_EUI_SIZE);
	memcpy(rq.node_nonce, node_nonce, LS_REJOIN_NONCE_SIZE);

	ls_frame_init(&frame);
	ls_frame_set_type(&frame, LS_TYPE_REJOIN_REQ);
	ls_frame_set_src(&frame, LS_BCAST_ADDR);
	ls_frame_set_dst(&frame, LS_BCAST_ADDR);
	ls_frame_set_fcnt(&frame, 0);
	ls_frame_set_flags(&frame, 0);
	ls_frame_set_payload(&frame, (const uint8_t *)&rq, LS_REJOIN_REQ_PAYLOAD_SIZE);

	ret = ls_frame_sign(&frame, network_key);
	zassert_equal(ret, 0, "ls_frame_sign failed: %d", ret);

	memcpy(buf, frame.buf, LS_FRAME_SIZE(LS_REJOIN_REQ_PAYLOAD_SIZE));
}

/*
 * Derive the same session key a real node would from the coordinator's
 * REJOIN_ACCEPT reply, mirroring rejoin_hkdf_session_key() in rejoin.c.
 * Kept independent of that internal function so the test doesn't just
 * trivially agree with itself.
 */
static void derive_session_key(const uint8_t dev_eui[LS_DEV_EUI_SIZE],
			       const uint8_t node_nonce[LS_REJOIN_NONCE_SIZE],
			       const uint8_t coord_nonce[LS_REJOIN_NONCE_SIZE],
			       uint8_t key[LS_NETWORK_KEY_SIZE])
{
	uint8_t salt[LS_DEV_EUI_SIZE + LS_REJOIN_NONCE_SIZE + LS_REJOIN_NONCE_SIZE];
	const uint8_t info[] = "lora_star_session_v1";
	int ret;

	memcpy(salt, dev_eui, LS_DEV_EUI_SIZE);
	memcpy(salt + LS_DEV_EUI_SIZE, node_nonce, LS_REJOIN_NONCE_SIZE);
	memcpy(salt + LS_DEV_EUI_SIZE + LS_REJOIN_NONCE_SIZE, coord_nonce, LS_REJOIN_NONCE_SIZE);

	ret = ls_crypto_hkdf(test_network_key, LS_NETWORK_KEY_SIZE, salt, sizeof(salt),
			     info, sizeof(info) - 1, key);
	zassert_equal(ret, 0, "ls_crypto_hkdf failed: %d", ret);
}

/* --------------------------------------------------------------------------
 * Suite 1: Wire format / struct layout
 * -------------------------------------------------------------------------- */

ZTEST(lora_star_rejoin_format, test_rejoin_req_payload_size)
{
	zassert_equal(sizeof(struct ls_rejoin_req_payload), LS_REJOIN_REQ_PAYLOAD_SIZE,
		      "struct size %zu != macro %d",
		      sizeof(struct ls_rejoin_req_payload), LS_REJOIN_REQ_PAYLOAD_SIZE);
}

ZTEST(lora_star_rejoin_format, test_rejoin_accept_payload_size)
{
	zassert_equal(sizeof(struct ls_rejoin_accept_payload), LS_REJOIN_ACCEPT_PAYLOAD_SIZE,
		      "struct size %zu != macro %d",
		      sizeof(struct ls_rejoin_accept_payload), LS_REJOIN_ACCEPT_PAYLOAD_SIZE);
}

ZTEST(lora_star_rejoin_format, test_rejoin_req_payload_field_offsets)
{
	zassert_equal(offsetof(struct ls_rejoin_req_payload, dev_eui), 0);
	zassert_equal(offsetof(struct ls_rejoin_req_payload, node_nonce), LS_DEV_EUI_SIZE);
}

ZTEST(lora_star_rejoin_format, test_rejoin_accept_payload_field_offsets)
{
	zassert_equal(offsetof(struct ls_rejoin_accept_payload, coord_nonce), 0);
	zassert_equal(offsetof(struct ls_rejoin_accept_payload, short_addr),
		      LS_REJOIN_NONCE_SIZE);
}

ZTEST_SUITE(lora_star_rejoin_format, NULL, NULL, NULL, NULL, NULL);

/* --------------------------------------------------------------------------
 * Suite 2: Coordinator rejoin integration
 * -------------------------------------------------------------------------- */

static struct ls_ctx *g_ctx;

static void *rejoin_suite_setup(void)
{
	int ret;

	g_ctx = ls_init(ls_fake_radio_dev());
	zassert_not_null(g_ctx, "ls_init failed");

	ret = ls_init_coord(g_ctx);
	zassert_equal(ret, 0, "ls_init_coord failed: %d", ret);

	/* Fixed key so the test can sign REJOIN_REQ frames itself. */
	ls_set_network_key(g_ctx, test_network_key);

	return NULL;
}

static void rejoin_before(void *fixture)
{
	ARG_UNUSED(fixture);

	ls_fake_radio_reset();
	ls_mac_recv(g_ctx);
}

ZTEST(lora_star_rejoin_coord, test_rejoin_bad_mic_rejected)
{
	uint8_t nonce[LS_REJOIN_NONCE_SIZE] = {0x11, 0x22, 0x33, 0x44};
	uint8_t dev_eui[LS_DEV_EUI_SIZE] = {0xB0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
	uint8_t rq_buf[LS_FRAME_SIZE(LS_REJOIN_REQ_PAYLOAD_SIZE)] = {0};
	uint32_t sent_len;

	build_rejoin_req(rq_buf, sizeof(rq_buf), dev_eui, nonce, test_network_key);
	rq_buf[sizeof(rq_buf) - 1] ^= 0xFF; /* corrupt the MIC */

	ls_fake_radio_set_rx(rq_buf, sizeof(rq_buf), -40, 5);
	ls_fake_radio_trigger_rx();
	k_msleep(100);

	zassert_is_null(ls_fake_radio_get_tx(&sent_len),
			"REJOIN_REQ with a corrupted MIC must not get a reply");
	zassert_is_null(ls_coord_find_node_by_eui(dev_eui),
			"a rejected REJOIN_REQ must not register a node");
}

ZTEST(lora_star_rejoin_coord, test_rejoin_new_device_registers)
{
	uint8_t nonce[LS_REJOIN_NONCE_SIZE] = {0xAA, 0xBB, 0xCC, 0xDD};
	uint8_t dev_eui[LS_DEV_EUI_SIZE] = {0xB0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02};
	uint8_t rq_buf[LS_FRAME_SIZE(LS_REJOIN_REQ_PAYLOAD_SIZE)] = {0};
	const uint8_t *sent;
	uint32_t sent_len;
	struct ls_frame accept_frame;
	uint8_t *payload;
	size_t payload_len;
	const struct ls_rejoin_accept_payload *ra;
	uint8_t session_key[LS_NETWORK_KEY_SIZE];
	uint16_t short_addr;
	struct coord_node *node;
	int ret;

	build_rejoin_req(rq_buf, sizeof(rq_buf), dev_eui, nonce, test_network_key);

	ls_fake_radio_set_rx(rq_buf, sizeof(rq_buf), -40, 5);
	ls_fake_radio_trigger_rx();
	k_msleep(100);

	sent = ls_fake_radio_get_tx(&sent_len);
	zassert_not_null(sent, "coordinator must reply to a valid REJOIN_REQ");
	zassert_equal(sent_len, LS_FRAME_SIZE(LS_REJOIN_ACCEPT_PAYLOAD_SIZE),
		      "unexpected REJOIN_ACCEPT frame size: %u", sent_len);
	zassert_equal(sent[0], LS_TYPE_REJOIN_ACCEPT,
		      "expected a REJOIN_ACCEPT frame, got type 0x%02x", sent[0]);

	node = ls_coord_find_node_by_eui(dev_eui);
	zassert_not_null(node, "a new DevEUI must be registered in the node table");
	zassert_true(node->session_active, "node must have an active session after rejoin");

	/* Verify the reply is authentic by deriving the session key ourselves. */
	ls_frame_init(&accept_frame);
	memcpy(accept_frame.buf, sent, sent_len);
	accept_frame.payload_len = LS_REJOIN_ACCEPT_PAYLOAD_SIZE;

	ls_frame_get_payload(&accept_frame, &payload, &payload_len);
	zassert_equal(payload_len, LS_REJOIN_ACCEPT_PAYLOAD_SIZE);
	ra = (const struct ls_rejoin_accept_payload *)payload;

	short_addr = sys_get_le16(ra->short_addr);
	zassert_equal(short_addr, node->short_addr,
		      "REJOIN_ACCEPT short_addr must match the node table entry");

	derive_session_key(dev_eui, nonce, ra->coord_nonce, session_key);
	ret = ls_frame_check_signature(&accept_frame, session_key);
	zassert_equal(ret, 0, "REJOIN_ACCEPT MIC must verify against the derived session key");
	zassert_mem_equal(session_key, node->session_key, LS_NETWORK_KEY_SIZE,
			   "derived session key must match what the coordinator installed");
}

ZTEST(lora_star_rejoin_coord, test_rejoin_known_device_reuses_addr)
{
	uint8_t nonce1[LS_REJOIN_NONCE_SIZE] = {0x01, 0x01, 0x01, 0x01};
	uint8_t nonce2[LS_REJOIN_NONCE_SIZE] = {0x02, 0x02, 0x02, 0x02};
	uint8_t dev_eui[LS_DEV_EUI_SIZE] = {0xB0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03};
	uint8_t rq_buf[LS_FRAME_SIZE(LS_REJOIN_REQ_PAYLOAD_SIZE)] = {0};
	struct coord_node *node;
	uint16_t addr_after_first;
	uint8_t session_key_after_first[LS_NETWORK_KEY_SIZE];
	uint32_t sent_len;

	/* First rejoin: registers the node and installs an initial session. */
	build_rejoin_req(rq_buf, sizeof(rq_buf), dev_eui, nonce1, test_network_key);
	ls_fake_radio_set_rx(rq_buf, sizeof(rq_buf), -40, 5);
	ls_fake_radio_trigger_rx();
	k_msleep(100);
	zassert_not_null(ls_fake_radio_get_tx(&sent_len), "first rejoin must be accepted");

	node = ls_coord_find_node_by_eui(dev_eui);
	zassert_not_null(node);
	addr_after_first = node->short_addr;
	memcpy(session_key_after_first, node->session_key, LS_NETWORK_KEY_SIZE);

	/*
	 * Second rejoin, same DevEUI, fresh nonce: same address, new session
	 * key. ls_fake_radio_reset() clears the fake driver's registered RX
	 * callback along with the recorded sent-frame state, so RX must be
	 * re-armed — same as rejoin_before() does at the start of every test.
	 */
	ls_fake_radio_reset();
	ls_mac_recv(g_ctx);
	build_rejoin_req(rq_buf, sizeof(rq_buf), dev_eui, nonce2, test_network_key);
	ls_fake_radio_set_rx(rq_buf, sizeof(rq_buf), -40, 5);
	ls_fake_radio_trigger_rx();
	k_msleep(100);
	zassert_not_null(ls_fake_radio_get_tx(&sent_len), "second rejoin must be accepted");

	node = ls_coord_find_node_by_eui(dev_eui);
	zassert_not_null(node);
	zassert_equal(node->short_addr, addr_after_first,
		      "re-rejoining the same DevEUI must keep its existing address");
	zassert_true(memcmp(node->session_key, session_key_after_first,
			     LS_NETWORK_KEY_SIZE) != 0,
		     "each rejoin must derive a fresh session key, even for the same node");
}

ZTEST_SUITE(lora_star_rejoin_coord, NULL, rejoin_suite_setup, rejoin_before, NULL, NULL);
