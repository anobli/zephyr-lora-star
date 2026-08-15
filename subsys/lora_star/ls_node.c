#include <string.h>
#include <errno.h>
#include <mbedtls/constant_time.h>
#include <zephyr/kernel.h>
#include <zephyr/drivers/lora.h>
#include <zephyr/drivers/hwinfo.h>
#include <zephyr/random/random.h>
#include <zephyr/logging/log.h>
#include <lora_star/lora_star.h>
#include <lora_star/ls_frame.h>
#include <lora_star/ls_crypto.h>
#include "ls_internal.h"
#include "ls_storage.h"

LOG_MODULE_REGISTER(ls_node, CONFIG_LORA_STAR_LOG_LEVEL);

static struct ls_node_ctx ls_node_instance;

/* --------------------------------------------------------------------------
 * Helpers
 * -------------------------------------------------------------------------- */

static int node_set_tx(struct ls_node_ctx *ctx, bool tx)
{
	ctx->radio_cfg.tx = tx;
	return lora_config(ctx->lora_dev, &ctx->radio_cfg);
}


/* --------------------------------------------------------------------------
 * Pairing
 * -------------------------------------------------------------------------- */

static int do_join_req(struct ls_node_ctx *ctx)
{
	if (ls_crypto_ecdh_gen_keypair(ctx->pub_key, ctx->priv_key) < 0) {
		return -EIO;
	}

	sys_csrand_get(ctx->join_nonce, sizeof(ctx->join_nonce));

	struct ls_join_req_payload jr = {0};

	memcpy(jr.dev_eui,      ctx->dev_eui,  LS_DEV_EUI_SIZE);
	memcpy(jr.node_pub_key, ctx->pub_key,  LS_PUBKEY_SIZE);
	memcpy(jr.nonce,        ctx->join_nonce, LS_NONCE_SIZE);

	uint8_t jr_key[LS_SESSION_KEY_SIZE];

	ls_crypto_join_req_key(ctx->dev_eui, jr_key);

	struct ls_frame_hdr hdr = {
		.type  = LS_TYPE_JOIN_REQ,
		.src   = 0x0000,
		.dst   = LS_BCAST_ADDR,
		.fcnt  = 0,
		.flags = 0,
	};

	uint8_t buf[LS_MAX_FRAME_SIZE];
	int hp_len = ls_frame_encode(buf, sizeof(buf), &hdr,
				     (const uint8_t *)&jr, sizeof(jr));
	if (hp_len < 0) {
		return hp_len;
	}

	if (ls_append_mic(buf, hp_len, jr_key) < 0) {
		return -EIO;
	}

	node_set_tx(ctx, true);
	int ret = lora_send(ctx->lora_dev, buf, hp_len + LS_MIC_SIZE);

	node_set_tx(ctx, false);
	return ret;
}

static void handle_join_accept(struct ls_node_ctx *ctx,
			       const uint8_t *buf, uint8_t len)
{
	struct ls_frame_hdr hdr;
	const uint8_t *payload;
	const uint8_t *rx_mic;
	uint8_t        payload_len;

	if (ls_frame_decode(buf, len, &hdr, &payload, &payload_len, &rx_mic) < 0) {
		return;
	}

	if (hdr.type != LS_TYPE_JOIN_ACCEPT ||
	    hdr.src  != LS_COORD_ADDR       ||
	    payload_len != LS_JOIN_ACCEPT_PAYLOAD_SIZE) {
		return;
	}

	const struct ls_join_accept_payload *ja =
		(const struct ls_join_accept_payload *)payload;

	uint8_t shared[LS_PUBKEY_SIZE];
	uint8_t new_key[LS_SESSION_KEY_SIZE];

	if (ls_crypto_ecdh_shared(ctx->priv_key, ja->coord_pub_key, shared) < 0 ||
	    ls_crypto_derive_session_key(shared, ctx->dev_eui,
					ctx->join_nonce, new_key) < 0) {
		LOG_ERR("Key derivation failed");
		memset(shared, 0, sizeof(shared));
		return;
	}

	uint8_t exp_mic[LS_MIC_SIZE];

	ls_crypto_compute_mic(new_key, buf, LS_HEADER_SIZE,
			      payload, payload_len, exp_mic);

	if (mbedtls_ct_memcmp(rx_mic, exp_mic, LS_MIC_SIZE) != 0) {
		LOG_WRN("JOIN_ACCEPT MIC mismatch");
		memset(shared, 0, sizeof(shared));
		return;
	}

	uint16_t new_addr;

	if (ls_crypto_decrypt_short_addr(shared, ctx->join_nonce,
					 ja->enc_short_addr, &new_addr) < 0) {
		LOG_ERR("ShortAddr decryption failed");
		memset(shared, 0, sizeof(shared));
		return;
	}

	memset(shared, 0, sizeof(shared));

	ctx->short_addr = new_addr;
	memcpy(ctx->session_key, new_key, LS_SESSION_KEY_SIZE);
	ctx->own_fcnt  = 0;
	ctx->fcnt_last = 0;

	memset(ctx->priv_key, 0, sizeof(ctx->priv_key));
	memset(ctx->pub_key,  0, sizeof(ctx->pub_key));

	ls_storage_node_save(ctx->short_addr, ctx->session_key, ctx->own_fcnt);

	ctx->state = NODE_JOINED;
	LOG_INF("Joined — ShortAddr 0x%04x", ctx->short_addr);
}

/* --------------------------------------------------------------------------
 * Data / ACK path
 * -------------------------------------------------------------------------- */

static int do_send(struct ls_node_ctx *ctx)
{
	uint8_t enc[LS_MAX_PAYLOAD_SIZE];

	ls_crypto_payload_crypt(ctx->session_key, ctx->own_fcnt, ctx->short_addr,
				ctx->pending_data, enc, ctx->pending_len);

	struct ls_frame_hdr hdr = {
		.type  = LS_TYPE_DATA,
		.src   = ctx->short_addr,
		.dst   = LS_COORD_ADDR,
		.fcnt  = ctx->own_fcnt++,
		.flags = LS_FLAG_ACK_REQ,
	};

	uint8_t buf[LS_MAX_FRAME_SIZE];
	int hp_len = ls_frame_encode(buf, sizeof(buf), &hdr, enc, ctx->pending_len);

	if (hp_len < 0) {
		return hp_len;
	}

	if (ls_append_mic(buf, hp_len, ctx->session_key) < 0) {
		return -EIO;
	}

	ls_storage_node_save_fcnt(ctx->own_fcnt);

	node_set_tx(ctx, true);
	int ret = lora_send(ctx->lora_dev, buf, hp_len + LS_MIC_SIZE);

	node_set_tx(ctx, false);
	return ret;
}

static void handle_ack(struct ls_node_ctx *ctx,
		       const uint8_t *buf, uint8_t len)
{
	struct ls_frame_hdr hdr;
	const uint8_t *payload;
	const uint8_t *rx_mic;
	uint8_t        payload_len;

	if (ls_frame_decode(buf, len, &hdr, &payload, &payload_len, &rx_mic) < 0) {
		return;
	}

	if (hdr.type != LS_TYPE_ACK    ||
	    hdr.src  != LS_COORD_ADDR  ||
	    hdr.dst  != ctx->short_addr) {
		return;
	}

	if (hdr.fcnt <= ctx->fcnt_last) {
		LOG_WRN("ACK replay (fcnt %u <= last %u)",
			hdr.fcnt, ctx->fcnt_last);
		return;
	}

	uint8_t exp_mic[LS_MIC_SIZE];

	ls_crypto_compute_mic(ctx->session_key,
			      buf, LS_HEADER_SIZE,
			      payload, payload_len,
			      exp_mic);

	if (mbedtls_ct_memcmp(rx_mic, exp_mic, LS_MIC_SIZE) != 0) {
		LOG_WRN("ACK MIC mismatch");
		ctx->send_result = -EACCES;
		ctx->state       = NODE_JOINED;
		k_sem_give(&ctx->result_sem);
		return;
	}

	ctx->fcnt_last = hdr.fcnt;
	ls_storage_node_save_fcnt_last(ctx->fcnt_last);

	if ((hdr.flags & LS_FLAG_ACK_PENDING) && payload_len > 0) {
		uint8_t plain[LS_MAX_PAYLOAD_SIZE];

		ls_crypto_payload_crypt(ctx->session_key, hdr.fcnt, LS_COORD_ADDR,
					payload, plain, payload_len);

		if (ctx->recv_cb) {
			ctx->recv_cb(ctx, plain, payload_len);
		}
	}

	ctx->send_result = 0;
	ctx->state       = NODE_JOINED;
	k_sem_give(&ctx->result_sem);
}

/* --------------------------------------------------------------------------
 * Pairing work handler
 * -------------------------------------------------------------------------- */

static void pairing_work_handler(struct k_work *work)
{
	struct ls_node_ctx *ctx =
		CONTAINER_OF(work, struct ls_node_ctx, pairing_work);

	k_sem_give(&ctx->pairing_sem);
}

/* --------------------------------------------------------------------------
 * Protocol thread
 * -------------------------------------------------------------------------- */

static void node_thread_fn(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);
	struct ls_node_ctx *ctx = p1;

	uint8_t rx_buf[LS_MAX_FRAME_SIZE];
	int16_t rssi;
	int8_t  snr;
	int     n;

	node_set_tx(ctx, false);

	while (1) {
		switch (ctx->state) {

		case NODE_UNJOINED:
			k_sem_take(&ctx->pairing_sem, K_FOREVER);
			if (do_join_req(ctx) == 0) {
				ctx->state       = NODE_JOINING;
				ctx->retry_count = 0;
			}
			break;

		case NODE_JOINING:
			n = lora_recv(ctx->lora_dev, rx_buf, sizeof(rx_buf),
				      K_MSEC(CONFIG_LORA_STAR_RX_WINDOW_MS),
				      &rssi, &snr);
			if (n > 0) {
				handle_join_accept(ctx, rx_buf, n);
			} else if (n == -EAGAIN) {
				if (++ctx->retry_count >=
				    CONFIG_LORA_STAR_TX_MAX_RETRIES) {
					LOG_WRN("Join timed out");
					ctx->state       = NODE_UNJOINED;
					ctx->retry_count = 0;
				} else {
					uint32_t jitter =
						sys_rand32_get() %
						CONFIG_LORA_STAR_TX_RETRY_BACKOFF_MS;
					k_msleep(CONFIG_LORA_STAR_TX_RETRY_BACKOFF_MS +
						 jitter);
					if (do_join_req(ctx) < 0) {
						LOG_ERR("JOIN_REQ retransmit failed, aborting join");
						ctx->state       = NODE_UNJOINED;
						ctx->retry_count = 0;
					}
				}
			}
			break;

		case NODE_JOINED:
			k_sem_take(&ctx->send_sem, K_FOREVER);
			ctx->retry_count = 0;
			if (do_send(ctx) == 0) {
				ctx->state = NODE_WAITING_ACK;
			} else {
				ctx->send_result = -EIO;
				k_sem_give(&ctx->result_sem);
			}
			break;

		case NODE_WAITING_ACK:
			n = lora_recv(ctx->lora_dev, rx_buf, sizeof(rx_buf),
				      K_MSEC(CONFIG_LORA_STAR_RX_WINDOW_MS),
				      &rssi, &snr);
			if (n > 0) {
				handle_ack(ctx, rx_buf, n);
			} else if (n == -EAGAIN) {
				if (++ctx->retry_count >=
				    CONFIG_LORA_STAR_TX_MAX_RETRIES) {
					LOG_WRN("ACK timed out after %d retries",
						CONFIG_LORA_STAR_TX_MAX_RETRIES);
					ctx->send_result = -ETIMEDOUT;
					ctx->state       = NODE_JOINED;
					k_sem_give(&ctx->result_sem);
				} else {
					uint32_t jitter =
						sys_rand32_get() %
						CONFIG_LORA_STAR_TX_RETRY_BACKOFF_MS;
					k_msleep(CONFIG_LORA_STAR_TX_RETRY_BACKOFF_MS +
						 jitter);
					do_send(ctx);
				}
			}
			break;
		}
	}
}

K_THREAD_DEFINE(ls_node_tid, CONFIG_LORA_STAR_THREAD_STACK_SIZE,
		node_thread_fn, &ls_node_instance, NULL, NULL,
		CONFIG_LORA_STAR_THREAD_PRIORITY, 0, -1);

/* --------------------------------------------------------------------------
 * Public API
 * -------------------------------------------------------------------------- */

struct ls_node_ctx *ls_init_node(const struct device *lora_dev)
{
	ls_node_instance.lora_dev = lora_dev;
	ls_node_instance.state    = NODE_UNJOINED;
	ls_node_instance.recv_cb  = NULL;

	ls_node_instance.radio_cfg = (struct lora_modem_config){
		.frequency    = CONFIG_LORA_STAR_FREQUENCY,
		.bandwidth    = BW_125_KHZ,
		.datarate     = SF_7,
		.coding_rate  = CR_4_5,
		.preamble_len = 8,
		.tx_power     = CONFIG_LORA_STAR_TX_POWER_DBM,
		.tx           = false,
	};

	k_sem_init(&ls_node_instance.pairing_sem, 0, 1);
	k_sem_init(&ls_node_instance.send_sem,    0, 1);
	k_sem_init(&ls_node_instance.result_sem,  0, 1);
	k_mutex_init(&ls_node_instance.send_lock);
	k_work_init(&ls_node_instance.pairing_work, pairing_work_handler);

	hwinfo_get_device_id(ls_node_instance.dev_eui,
			     sizeof(ls_node_instance.dev_eui));

	int ret = ls_storage_node_load(&ls_node_instance.short_addr,
				       ls_node_instance.session_key,
				       &ls_node_instance.own_fcnt,
				       &ls_node_instance.fcnt_last);
	if (ret == 0) {
		ls_node_instance.own_fcnt += CONFIG_LORA_STAR_FCNT_REBOOT_INCREMENT;
		ls_storage_node_save_fcnt(ls_node_instance.own_fcnt);
		ls_node_instance.state = NODE_JOINED;
		LOG_INF("Restored session — ShortAddr 0x%04x",
			ls_node_instance.short_addr);
	} else if (ret == -ENOENT) {
		ls_node_instance.state = NODE_UNJOINED;
	} else {
		return NULL;
	}

	k_thread_start(ls_node_tid);

	return &ls_node_instance;
}

void ls_node_start_pairing(struct ls_node_ctx *ctx)
{
	k_work_submit(&ctx->pairing_work);
}

int ls_node_send(struct ls_node_ctx *ctx, const uint8_t *data, uint8_t len)
{
	if (len > LS_MAX_PAYLOAD_SIZE) {
		return -EINVAL;
	}

	k_mutex_lock(&ctx->send_lock, K_FOREVER);

	if (ctx->state != NODE_JOINED) {
		k_mutex_unlock(&ctx->send_lock);
		return -ENOTCONN;
	}

	if (k_sem_count_get(&ctx->send_sem) > 0) {
		k_mutex_unlock(&ctx->send_lock);
		return -EBUSY;
	}

	memcpy(ctx->pending_data, data, len);
	ctx->pending_len = len;
	k_sem_give(&ctx->send_sem);

	k_mutex_unlock(&ctx->send_lock);

	k_sem_take(&ctx->result_sem, K_FOREVER);

	return ctx->send_result;
}

void ls_node_set_recv_cb(struct ls_node_ctx *ctx, ls_node_recv_cb cb)
{
	ctx->recv_cb = cb;
}
