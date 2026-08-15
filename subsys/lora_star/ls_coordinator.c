#include <string.h>
#include <errno.h>
#include <mbedtls/constant_time.h>
#include <zephyr/kernel.h>
#include <zephyr/drivers/lora.h>
#include <zephyr/random/random.h>
#include <zephyr/logging/log.h>
#include <lora_star/lora_star.h>
#include <lora_star/ls_frame.h>
#include <lora_star/ls_crypto.h>
#include "ls_internal.h"
#include "ls_storage.h"

LOG_MODULE_REGISTER(ls_coord, CONFIG_LORA_STAR_LOG_LEVEL);

#define COORD_RX_QUEUE_DEPTH 8

static struct ls_coord_ctx ls_coord_instance;
static char coord_rx_msgq_buf[COORD_RX_QUEUE_DEPTH * sizeof(struct coord_rx_frame)];

/* --------------------------------------------------------------------------
 * Helpers
 * -------------------------------------------------------------------------- */

static int coord_set_tx(struct ls_coord_ctx *ctx, bool tx)
{
	ctx->radio_cfg.tx = tx;
	return lora_config(ctx->lora_dev, &ctx->radio_cfg);
}

static void coord_rx_cb(const struct device *dev, uint8_t *data, uint16_t size,
			int16_t rssi, int8_t snr, void *user_data)
{
	struct ls_coord_ctx *ctx = user_data;
	struct coord_rx_frame frame;

	ARG_UNUSED(dev);
	ARG_UNUSED(snr);

	if (!data || size == 0 || size > sizeof(frame.data)) {
		return;
	}

	frame.len  = (uint8_t)size;
	frame.rssi = rssi;
	memcpy(frame.data, data, size);

	if (k_msgq_put(&ctx->rx_msgq, &frame, K_NO_WAIT) < 0) {
		LOG_WRN("RX queue full — frame dropped");
	}
}

static void coord_rx_start(struct ls_coord_ctx *ctx)
{
	coord_set_tx(ctx, false);
	lora_recv_async(ctx->lora_dev, coord_rx_cb, ctx);
}

static void coord_rx_stop(struct ls_coord_ctx *ctx)
{
	lora_recv_async(ctx->lora_dev, NULL, NULL);
}

static int coord_send_frame(struct ls_coord_ctx *ctx, uint8_t *buf, uint8_t len)
{
	int ret;

	coord_rx_stop(ctx);
	coord_set_tx(ctx, true);
	ret = lora_send(ctx->lora_dev, buf, len);
	coord_rx_start(ctx);

	return ret;
}

static int coord_find_node(struct ls_coord_ctx *ctx, uint16_t addr)
{
	for (int i = 0; i < CONFIG_LORA_STAR_MAX_NODES; i++) {
		if (ctx->nodes[i].active && ctx->nodes[i].short_addr == addr) {
			return i;
		}
	}
	return -ENOENT;
}

static int coord_alloc_node(struct ls_coord_ctx *ctx)
{
	for (int i = 0; i < CONFIG_LORA_STAR_MAX_NODES; i++) {
		if (!ctx->nodes[i].active) {
			return i;
		}
	}
	return -ENOMEM;
}

static int coord_find_node_by_eui(struct ls_coord_ctx *ctx,
				   const uint8_t dev_eui[LS_DEV_EUI_SIZE])
{
	for (int i = 0; i < CONFIG_LORA_STAR_MAX_NODES; i++) {
		if (ctx->nodes[i].active &&
		    memcmp(ctx->nodes[i].rec.dev_eui, dev_eui,
			   LS_DEV_EUI_SIZE) == 0) {
			return i;
		}
	}
	return -ENOENT;
}


/* --------------------------------------------------------------------------
 * Storage load callback
 * -------------------------------------------------------------------------- */

static void on_node_loaded(uint16_t short_addr, const struct ls_node_record *rec,
			   void *user_data)
{
	struct ls_coord_ctx *ctx = user_data;
	int slot = coord_alloc_node(ctx);

	if (slot < 0) {
		LOG_WRN("Node table full — dropping addr 0x%04x", short_addr);
		return;
	}

	ctx->nodes[slot].short_addr = short_addr;
	ctx->nodes[slot].rec        = *rec;
	ctx->nodes[slot].active     = true;

	LOG_DBG("Loaded node 0x%04x", short_addr);
}

/* --------------------------------------------------------------------------
 * JOIN_REQ handler
 * -------------------------------------------------------------------------- */

static void handle_join_req(struct ls_coord_ctx *ctx,
			    const uint8_t *buf, uint8_t len, int16_t rssi)
{
	if (ctx->state != COORD_PAIRING) {
		LOG_DBG("JOIN_REQ ignored: not in pairing mode");
		return;
	}

	if (rssi < CONFIG_LORA_STAR_PAIRING_RSSI_THRESHOLD_DBM) {
		LOG_DBG("JOIN_REQ rejected: RSSI %d < threshold %d",
			rssi, CONFIG_LORA_STAR_PAIRING_RSSI_THRESHOLD_DBM);
		return;
	}

	struct ls_frame_hdr hdr;
	const uint8_t *payload;
	const uint8_t *rx_mic;
	uint8_t        payload_len;

	if (ls_frame_decode(buf, len, &hdr, &payload, &payload_len, &rx_mic) < 0) {
		return;
	}

	if (hdr.type != LS_TYPE_JOIN_REQ ||
	    payload_len != LS_JOIN_REQ_PAYLOAD_SIZE) {
		return;
	}

	const struct ls_join_req_payload *jr =
		(const struct ls_join_req_payload *)payload;

	uint8_t jr_key[LS_SESSION_KEY_SIZE];
	uint8_t exp_mic[LS_MIC_SIZE];

	ls_crypto_join_req_key(jr->dev_eui, jr_key);
	ls_crypto_compute_mic(jr_key, buf, LS_HEADER_SIZE,
			      payload, payload_len, exp_mic);

	if (mbedtls_ct_memcmp(rx_mic, exp_mic, LS_MIC_SIZE) != 0) {
		LOG_WRN("JOIN_REQ MIC mismatch");
		return;
	}

	int slot = coord_find_node_by_eui(ctx, jr->dev_eui);
	bool is_repair = (slot >= 0);

	if (!is_repair) {
		slot = coord_alloc_node(ctx);
		if (slot < 0) {
			LOG_ERR("Node table full");
			return;
		}
	}

	if (!ctx->keypair_ready) {
		if (ls_crypto_ecdh_gen_keypair(ctx->pub_key, ctx->priv_key) < 0) {
			LOG_ERR("ECDH keygen failed");
			return;
		}
		ctx->keypair_ready = true;
	}

	uint8_t shared[LS_PUBKEY_SIZE];
	uint8_t session_key[LS_SESSION_KEY_SIZE];

	if (ls_crypto_ecdh_shared(ctx->priv_key, jr->node_pub_key, shared) < 0 ||
	    ls_crypto_derive_session_key(shared, jr->dev_eui, jr->nonce,
					session_key) < 0) {
		LOG_ERR("Key derivation failed");
		memset(shared, 0, sizeof(shared));
		return;
	}

	uint16_t short_addr;

	if (is_repair) {
		short_addr = ctx->nodes[slot].short_addr;
	} else {
		if (ctx->next_addr > LS_ADDR_MAX) {
			LOG_ERR("Address space exhausted");
			memset(shared, 0, sizeof(shared));
			return;
		}
		short_addr = ctx->next_addr++;
	}

	uint16_t enc_addr;

	if (ls_crypto_encrypt_short_addr(shared, jr->nonce,
					 short_addr, &enc_addr) < 0) {
		LOG_ERR("ShortAddr encryption failed");
		memset(shared, 0, sizeof(shared));
		return;
	}

	memset(shared, 0, sizeof(shared));

	struct ls_join_accept_payload ja = {
		.enc_short_addr = enc_addr,
	};
	memcpy(ja.coord_pub_key, ctx->pub_key, LS_PUBKEY_SIZE);

	struct ls_frame_hdr tx_hdr = {
		.type  = LS_TYPE_JOIN_ACCEPT,
		.src   = LS_COORD_ADDR,
		.dst   = LS_BCAST_ADDR,
		.fcnt  = ctx->fcnt++,
		.flags = 0,
	};

	uint8_t tx_buf[LS_MAX_FRAME_SIZE];
	int hdr_payload_len = ls_frame_encode(tx_buf, sizeof(tx_buf),
					      &tx_hdr,
					      (const uint8_t *)&ja, sizeof(ja));
	if (hdr_payload_len < 0) {
		return;
	}

	if (ls_append_mic(tx_buf, hdr_payload_len, session_key) < 0) {
		return;
	}

	coord_send_frame(ctx, tx_buf, hdr_payload_len + LS_MIC_SIZE);

	memset(ctx->priv_key, 0, sizeof(ctx->priv_key));
	memset(ctx->pub_key, 0, sizeof(ctx->pub_key));
	ctx->keypair_ready = false;

	struct ls_node_record rec = {
		.fcnt_last = 0,
	};
	memcpy(rec.dev_eui,     jr->dev_eui, LS_DEV_EUI_SIZE);
	memcpy(rec.session_key, session_key, LS_SESSION_KEY_SIZE);

	ctx->nodes[slot].short_addr = short_addr;
	ctx->nodes[slot].rec        = rec;
	ctx->nodes[slot].active     = true;

	ls_storage_coord_save_node(short_addr, &rec);
	if (!is_repair) {
		ls_storage_coord_save_next_addr(ctx->next_addr);
	}
	ls_storage_coord_save_fcnt(ctx->fcnt);

	k_work_cancel_delayable(&ctx->pairing_close_work);
	ctx->state = COORD_IDLE;

	LOG_INF("Node 0x%04x %s", short_addr, is_repair ? "re-paired" : "joined");

	if (ctx->join_cb) {
		ctx->join_cb(ctx, short_addr, jr->dev_eui);
	}
}

/* --------------------------------------------------------------------------
 * DATA handler
 * -------------------------------------------------------------------------- */

static void handle_data(struct ls_coord_ctx *ctx,
			const uint8_t *buf, uint8_t len)
{
	struct ls_frame_hdr hdr;
	const uint8_t *payload;
	const uint8_t *rx_mic;
	uint8_t        payload_len;

	if (ls_frame_decode(buf, len, &hdr, &payload, &payload_len, &rx_mic) < 0) {
		return;
	}

	if (hdr.dst != LS_COORD_ADDR) {
		return;
	}

	int slot = coord_find_node(ctx, hdr.src);

	if (slot < 0) {
		LOG_WRN("DATA from unknown node 0x%04x", hdr.src);
		return;
	}

	struct coord_node *n = &ctx->nodes[slot];

	if (hdr.fcnt <= n->rec.fcnt_last) {
		LOG_WRN("Replay from 0x%04x (fcnt %u <= last %u)",
			hdr.src, hdr.fcnt, n->rec.fcnt_last);
		return;
	}

	uint8_t exp_mic[LS_MIC_SIZE];

	ls_crypto_compute_mic(n->rec.session_key,
			      buf, LS_HEADER_SIZE,
			      payload, payload_len,
			      exp_mic);

	if (mbedtls_ct_memcmp(rx_mic, exp_mic, LS_MIC_SIZE) != 0) {
		LOG_WRN("DATA MIC mismatch from 0x%04x", hdr.src);
		return;
	}

	uint8_t plain[LS_MAX_PAYLOAD_SIZE];

	if (payload_len > 0) {
		ls_crypto_payload_crypt(n->rec.session_key, hdr.fcnt, hdr.src,
					payload, plain, payload_len);
	}

	n->rec.fcnt_last = hdr.fcnt;
	ls_storage_coord_save_node(n->short_addr, &n->rec);

	if (ctx->recv_cb && payload_len > 0) {
		ctx->recv_cb(ctx, hdr.src, plain, payload_len);
	}

	if (!(hdr.flags & LS_FLAG_ACK_REQ)) {
		return;
	}

	uint8_t dl_data[LS_MAX_PAYLOAD_SIZE];
	uint8_t dl_len = 0;
	bool    dl_pending = false;

	k_mutex_lock(&ctx->dl_mutex, K_FOREVER);
	if (ctx->downlinks[slot].pending) {
		memcpy(dl_data, ctx->downlinks[slot].data,
		       ctx->downlinks[slot].len);
		dl_len     = ctx->downlinks[slot].len;
		dl_pending = true;
		ctx->downlinks[slot].pending = false;
	}
	k_mutex_unlock(&ctx->dl_mutex);

	struct ls_frame_hdr ack_hdr = {
		.type  = LS_TYPE_ACK,
		.src   = LS_COORD_ADDR,
		.dst   = hdr.src,
		.fcnt  = ctx->fcnt++,
		.flags = dl_pending ? LS_FLAG_ACK_PENDING : 0,
	};

	uint8_t enc_dl[LS_MAX_PAYLOAD_SIZE];
	const uint8_t *ack_payload     = NULL;
	uint8_t        ack_payload_len = 0;

	if (dl_pending) {
		ls_crypto_payload_crypt(n->rec.session_key,
					ack_hdr.fcnt, LS_COORD_ADDR,
					dl_data, enc_dl, dl_len);
		ack_payload     = enc_dl;
		ack_payload_len = dl_len;
	}

	uint8_t tx_buf[LS_MAX_FRAME_SIZE];
	int hp_len = ls_frame_encode(tx_buf, sizeof(tx_buf), &ack_hdr,
				     ack_payload, ack_payload_len);
	if (hp_len < 0) {
		return;
	}

	if (ls_append_mic(tx_buf, hp_len, n->rec.session_key) < 0) {
		return;
	}

	ls_storage_coord_save_fcnt(ctx->fcnt);

	coord_send_frame(ctx, tx_buf, hp_len + LS_MIC_SIZE);
}

/* --------------------------------------------------------------------------
 * Pairing work handler
 * -------------------------------------------------------------------------- */

static void pairing_close_work_handler(struct k_work *work)
{
	struct ls_coord_ctx *ctx =
		CONTAINER_OF(work, struct ls_coord_ctx, pairing_close_work.work);

	ctx->state = COORD_IDLE;
	LOG_INF("Pairing window closed");
}

static void pairing_work_handler(struct k_work *work)
{
	struct ls_coord_ctx *ctx =
		CONTAINER_OF(work, struct ls_coord_ctx, pairing_work);

	ctx->keypair_ready = false;

	if (ls_crypto_ecdh_gen_keypair(ctx->pub_key, ctx->priv_key) < 0) {
		LOG_ERR("ECDH keygen failed; pairing not started");
		return;
	}
	ctx->keypair_ready = true;

	ctx->state = COORD_PAIRING;
	k_work_schedule(&ctx->pairing_close_work,
			K_SECONDS(CONFIG_LORA_STAR_PAIRING_WINDOW_S));
	LOG_INF("Pairing window open (%d s)", CONFIG_LORA_STAR_PAIRING_WINDOW_S);
}

/* --------------------------------------------------------------------------
 * Protocol thread
 * -------------------------------------------------------------------------- */

static void coord_thread_fn(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);
	struct ls_coord_ctx *ctx = p1;
	struct coord_rx_frame frame;

	coord_rx_start(ctx);

	while (1) {
		k_msgq_get(&ctx->rx_msgq, &frame, K_FOREVER);

		switch (frame.data[0]) {
		case LS_TYPE_JOIN_REQ:
			handle_join_req(ctx, frame.data, frame.len, frame.rssi);
			break;
		case LS_TYPE_DATA:
			handle_data(ctx, frame.data, frame.len);
			break;
		default:
			break;
		}
	}
}

K_THREAD_DEFINE(ls_coord_tid, CONFIG_LORA_STAR_THREAD_STACK_SIZE,
		coord_thread_fn, &ls_coord_instance, NULL, NULL,
		CONFIG_LORA_STAR_THREAD_PRIORITY, 0, -1);

/* --------------------------------------------------------------------------
 * Public API
 * -------------------------------------------------------------------------- */

struct ls_coord_ctx *ls_init_coordinator(const struct device *lora_dev)
{
	ls_coord_instance.lora_dev  = lora_dev;
	ls_coord_instance.state     = COORD_IDLE;
	ls_coord_instance.recv_cb   = NULL;
	ls_coord_instance.join_cb   = NULL;

	ls_coord_instance.radio_cfg = (struct lora_modem_config){
		.frequency    = CONFIG_LORA_STAR_FREQUENCY,
		.bandwidth    = BW_125_KHZ,
		.datarate     = SF_7,
		.coding_rate  = CR_4_5,
		.preamble_len = 8,
		.tx_power     = CONFIG_LORA_STAR_TX_POWER_DBM,
		.tx           = false,
	};

	k_mutex_init(&ls_coord_instance.dl_mutex);
	k_work_init(&ls_coord_instance.pairing_work, pairing_work_handler);
	k_work_init_delayable(&ls_coord_instance.pairing_close_work,
			      pairing_close_work_handler);
	k_msgq_init(&ls_coord_instance.rx_msgq, coord_rx_msgq_buf,
		    sizeof(struct coord_rx_frame), COORD_RX_QUEUE_DEPTH);

	int ret = ls_storage_coord_load(&ls_coord_instance.next_addr,
					&ls_coord_instance.fcnt,
					on_node_loaded, &ls_coord_instance);
	if (ret < 0) {
		return NULL;
	}

	ls_coord_instance.fcnt += CONFIG_LORA_STAR_FCNT_REBOOT_INCREMENT;
	ls_storage_coord_save_fcnt(ls_coord_instance.fcnt);

	k_thread_start(ls_coord_tid);

	return &ls_coord_instance;
}

void ls_coord_start_pairing(struct ls_coord_ctx *ctx)
{
	k_work_submit(&ctx->pairing_work);
}

int ls_coord_send(struct ls_coord_ctx *ctx, uint16_t short_addr,
		  const uint8_t *data, uint8_t len)
{
	if (len > LS_MAX_PAYLOAD_SIZE) {
		return -EINVAL;
	}

	int slot = coord_find_node(ctx, short_addr);

	if (slot < 0) {
		return -ENOENT;
	}

	k_mutex_lock(&ctx->dl_mutex, K_FOREVER);
	memcpy(ctx->downlinks[slot].data, data, len);
	ctx->downlinks[slot].len     = len;
	ctx->downlinks[slot].pending = true;
	k_mutex_unlock(&ctx->dl_mutex);

	return 0;
}

void ls_coord_set_recv_cb(struct ls_coord_ctx *ctx, ls_coord_recv_cb cb)
{
	ctx->recv_cb = cb;
}

void ls_coord_set_join_cb(struct ls_coord_ctx *ctx, ls_coord_join_cb cb)
{
	ctx->join_cb = cb;
}
