/*
 * Copyright (c) 2026 Alexandre Bailon <abailon@baylibre.com>
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#include <psa/crypto.h>
#include <zephyr/sys/util.h>
#include <mbedtls/constant_time.h>
#include <zephyr/kernel.h>
#include <zephyr/random/random.h>
#include <zephyr/logging/log.h>

#include <lora_star/lora_star.h>
#include <lora_star/mac.h>
#include <lora_star/radio.h>

#include "storage.h"

LOG_MODULE_REGISTER(lora_star, CONFIG_LORA_STAR_LOG_LEVEL);

#ifdef CONFIG_LORA_STAR_DEFAULT_NETWORK_KEY
static void apply_default_network_key(struct ls_ctx *ctx)
{
	const char *hex = CONFIG_LORA_STAR_DEFAULT_NETWORK_KEY_VALUE;
	size_t n;

	n = hex2bin(hex, strlen(hex), ctx->network_key, LS_NETWORK_KEY_SIZE);
	if (n != LS_NETWORK_KEY_SIZE) {
		LOG_ERR("Default network key must be %d hex chars",
			2 * LS_NETWORK_KEY_SIZE);
		memset(ctx->network_key, 0, LS_NETWORK_KEY_SIZE);
	}
}
#endif

static struct ls_ctx ls_ctx_instance;

struct ls_tx_cmd {
	struct ls_ctx *ctx;
	uint16_t       dst;
	bool           want_ack;
	ls_send_cb     done_cb;
	void          *user_data;
	uint8_t        data[LS_MAX_PAYLOAD_SIZE];
	size_t         len;
	/* When non-NULL, fn(ctx, user_data) runs instead of a data send. */
	int          (*fn)(struct ls_ctx *, void *);
};

static void ls_thread_fn(void *p1, void *p2, void *p3);
static void ls_tx_thread_fn(void *p1, void *p2, void *p3);

K_MSGQ_DEFINE(ls_tx_msgq, sizeof(struct ls_tx_cmd),
	      CONFIG_LORA_STAR_TX_MSGQ_DEPTH, 4);

K_THREAD_DEFINE(ls_tx_tid, CONFIG_LORA_STAR_TX_THREAD_STACK_SIZE,
		ls_tx_thread_fn, NULL, NULL, NULL,
		CONFIG_LORA_STAR_TX_THREAD_PRIORITY, 0, -1);

K_THREAD_DEFINE(ls_tid, CONFIG_LORA_STAR_THREAD_STACK_SIZE,
		ls_thread_fn, &ls_ctx_instance, NULL, NULL,
		CONFIG_LORA_STAR_THREAD_PRIORITY, 0, -1);

struct ls_ctx *ls_init(const struct device *lora_dev)
{
	struct ls_ctx *ctx = &ls_ctx_instance;
	int ret;

	if (!lora_dev) {
		return NULL;
	}

	ctx->radio_dev = lora_dev;
	ctx->own_addr = LS_COORD_ADDR;
	ctx->fcnt = 0;
	ctx->always_on_rx = false;
	memset(ctx->network_key, 0, sizeof(ctx->network_key));
	memset(ctx->_handlers, 0, sizeof(ctx->_handlers));

	k_msgq_init(&ctx->_msgq, ctx->_msgq_buf, sizeof(struct ls_frame),
		     CONFIG_LORA_STAR_MSGQ_DEPTH);
	k_mutex_init(&ctx->_handlers_lock);

	/*
	 * Attempt to restore a persisted node session before starting RX so
	 * the MAC has the correct session key from the first received frame.
	 * ENOENT means no session was ever saved (e.g. coordinator or
	 * unpaired node); other errors are logged but not fatal.
	 */
	ret = ls_mac_init(ctx);
	if (ret) {
		return NULL;
	}

	ret = ls_storage_init();
	if (ret < 0) {
		LOG_WRN("Storage init failed: %d", ret);
		goto done;
	}

	ls_storage_load_fcnt(ctx);
	ls_storage_load_network_key(ctx);

#ifdef CONFIG_LORA_STAR_DEFAULT_NETWORK_KEY
	if (!ctx->network_key_found) {
		apply_default_network_key(ctx);
	}
#endif

	ret = ls_storage_load_addr(ctx);
	if (ret == 0 && ctx->addr_found) {
		ctx->fcnt += CONFIG_LORA_STAR_FCNT_REBOOT_INCREMENT;
		ls_storage_save_fcnt(ctx);
		LOG_INF("Session restored — ShortAddr 0x%04x", ctx->own_addr);
	}

done:

	k_thread_start(ls_tx_tid);
	k_thread_start(ls_tid);

	return ctx;
}

#ifdef CONFIG_LORA_STAR_COORDINATOR
int ls_init_coord(struct ls_ctx *ctx)
{
#ifdef CONFIG_LORA_STAR_DEFAULT_NETWORK_KEY
	if (!ctx->network_key_found) {
		LOG_INF("Using compile-time default network key");
	} else {
		LOG_INF("Restored network key");
	}
#else
	psa_status_t st;
	int ret;

	if (!ctx->network_key_found) {
		st = psa_generate_random(ctx->network_key, sizeof(ctx->network_key));
		if (st != PSA_SUCCESS) {
			return -EIO;
		}
		ret = ls_storage_save_network_key(ctx);
		if (ret < 0) {
			memset(ctx->network_key, 0, sizeof(ctx->network_key));
			return ret;
		}
		LOG_INF("Generated new network key");
	} else {
		LOG_INF("Restored network key");
	}
#endif

	ctx->fcnt += CONFIG_LORA_STAR_FCNT_REBOOT_INCREMENT;
	ls_storage_save_fcnt(ctx);
	ls_set_own_addr(ctx, LS_COORD_ADDR);
	ctx->always_on_rx = true;
	ls_mac_recv(ctx);

	return 0;
}
#endif

bool ls_is_network_key_set(const struct ls_ctx *ctx)
{
	static const uint8_t zero[LS_NETWORK_KEY_SIZE] = {0};

	return mbedtls_ct_memcmp(ctx->network_key, zero, LS_NETWORK_KEY_SIZE) != 0;
}

bool ls_is_paired(const struct ls_ctx *ctx)
{
	return ls_is_network_key_set(ctx) &&
	       ctx->own_addr != LS_COORD_ADDR;
}

void ls_set_network_key(struct ls_ctx *ctx, const uint8_t key[LS_NETWORK_KEY_SIZE])
{
	memcpy(ctx->network_key, key, LS_NETWORK_KEY_SIZE);
}

void ls_set_own_addr(struct ls_ctx *ctx, uint16_t addr)
{
	ctx->own_addr = addr;
}

struct ls_frame_handler *ls_register_frame_cb(struct ls_ctx *ctx,
					      const struct ls_frame_filter *filter,
					      ls_frame_cb cb, void *user_data)
{
	struct ls_frame_handler *handler = NULL;
	int i;

	k_mutex_lock(&ctx->_handlers_lock, K_FOREVER);

	for (i = 0; i < CONFIG_LORA_STAR_MAX_FRAME_CBS; i++) {
		if (ctx->_handlers[i].cb == NULL) {
			handler = &ctx->_handlers[i];
			handler->filter    = *filter;
			handler->user_data = user_data;
			handler->cb        = cb;
			break;
		}
	}

	k_mutex_unlock(&ctx->_handlers_lock);
	return handler;
}

struct ls_frame_handler *ls_register_data_cb(struct ls_ctx *ctx, uint16_t dst,
					     ls_frame_cb cb, void *user_data)
{
	struct ls_frame_filter filter = {
		.type = LS_TYPE_DATA,
		.src  = LS_BCAST_ADDR,
		.dst  = dst,
	};

	return ls_register_frame_cb(ctx, &filter, cb, user_data);
}

void ls_unregister_frame_cb(struct ls_ctx *ctx, struct ls_frame_handler *handler)
{
	ARG_UNUSED(ctx);

	if (handler) {
		handler->cb = NULL;
	}
}

static bool frame_matches_filter(struct ls_frame *frame,
				 const struct ls_frame_filter *filter)
{
	if (filter->type != 0 && ls_frame_get_type(frame) != filter->type) {
		return false;
	}
	if (filter->src != LS_BCAST_ADDR && ls_frame_get_src(frame) != filter->src) {
		return false;
	}
	if (filter->dst != LS_BCAST_ADDR && ls_frame_get_dst(frame) != filter->dst) {
		return false;
	}
	return true;
}

static void ls_dispatch_frame(struct ls_ctx *ctx, struct ls_frame *frame)
{
	int i;

	k_mutex_lock(&ctx->_handlers_lock, K_FOREVER);

	for (i = 0; i < CONFIG_LORA_STAR_MAX_FRAME_CBS; i++) {
		if (ctx->_handlers[i].cb == NULL) {
			continue;
		}
		if (!frame_matches_filter(frame, &ctx->_handlers[i].filter)) {
			continue;
		}
		if (ctx->_handlers[i].cb(ctx, frame, ctx->_handlers[i].user_data) < 0) {
			break;
		}
	}

	k_mutex_unlock(&ctx->_handlers_lock);
}

static void ls_thread_fn(void *p1, void *p2, void *p3)
{
	struct ls_ctx *ctx = p1;
	struct ls_frame frame;

	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	LOG_INF("LoRa Star thread started");

	while (true) {
		k_msgq_get(&ctx->_msgq, &frame, K_FOREVER);
		ls_dispatch_frame(ctx, &frame);
		ls_frame_free_buf(&frame);
	}
}

int ls_send_ack(struct ls_ctx *ctx, uint16_t dst)
{
	struct ls_frame frame;
	int ret;

	ret = ls_frame_alloc_buf(&frame, 0);
	if (ret < 0) {
		return ret;
	}

	ls_frame_set_type(&frame, LS_TYPE_ACK);
	ls_frame_set_dst(&frame, dst);
	ls_frame_set_flags(&frame, 0);

	ret = ls_mac_send(ctx, &frame);
	ls_frame_free_buf(&frame);
	return ret;
}

static int ls_do_send(struct ls_ctx *ctx, uint16_t dst, const uint8_t *data,
		      size_t len, uint8_t flags)
{
	struct ls_frame frame;
	int ret;

	ret = ls_frame_alloc_buf(&frame, len);
	if (ret < 0) {
		return ret;
	}

	ls_frame_set_type(&frame, LS_TYPE_DATA);
	ls_frame_set_dst(&frame, dst);
	ls_frame_set_flags(&frame, flags);
	ls_frame_set_payload(&frame, data);

	ret = ls_mac_send(ctx, &frame);
	ls_frame_free_buf(&frame);
	return ret;
}

int ls_send_data(struct ls_ctx *ctx, uint16_t dst, const uint8_t *data, size_t len)
{
	return ls_do_send(ctx, dst, data, len, 0);
}

static int ack_recv_cb(struct ls_ctx *ctx, struct ls_frame *frame, void *user_data)
{
	struct k_sem *sem = user_data;

	ARG_UNUSED(ctx);
	ARG_UNUSED(frame);

	k_sem_give(sem);
	return -1;
}

static struct ls_frame_handler *ls_register_ack_handler(struct ls_ctx *ctx,
							uint16_t src,
							struct k_sem *sem)
{
	struct ls_frame_filter filter = {
		.type = LS_TYPE_ACK,
		.src  = src,
		.dst  = ctx->own_addr,
	};

	return ls_register_frame_cb(ctx, &filter, ack_recv_cb, sem);
}

int ls_send_data_ack(struct ls_ctx *ctx, uint16_t dst, const uint8_t *data, size_t len)
{
	struct k_sem ack_sem;
	struct ls_frame_handler *ack_handler;
	uint32_t timeout_ms;
	int retry;
	int ret;

	/*
	 * Timeout = time for our DATA frame to reach the peer
	 *         + time for the ACK to come back
	 *         + guard for the peer's processing and TX-switch latency.
	 * lora_airtime() uses the current modem config, so the radio must
	 * have been configured at least once before this call (guaranteed
	 * after pairing, which always involves radio activity).
	 */
	timeout_ms = ls_radio_airtime_ms(ctx->radio_dev, LS_FRAME_SIZE(len))
		   + ls_radio_airtime_ms(ctx->radio_dev, LS_FRAME_SIZE(0))
		   + CONFIG_LORA_STAR_ACK_GUARD_MS + 1000;

	k_sem_init(&ack_sem, 0, 1);

	ack_handler = ls_register_ack_handler(ctx, dst, &ack_sem);
	if (!ack_handler) {
		return -ENOMEM;
	}

	ret = -ETIMEDOUT;

	for (retry = 0; retry <= CONFIG_LORA_STAR_TX_MAX_RETRIES; retry++) {
		if (!ctx->always_on_rx) {
			ls_mac_rx_stop(ctx);
		}

		ret = ls_do_send(ctx, dst, data, len, LS_FLAG_ACK_REQ);
		if (ret < 0) {
			break;
		}

		if (!ctx->always_on_rx) {
			ls_mac_recv(ctx);
		}

		if (k_sem_take(&ack_sem, K_MSEC(timeout_ms)) == 0) {
			ret = 0;
			break;
		}

		ret = -ETIMEDOUT;

		if (retry < CONFIG_LORA_STAR_TX_MAX_RETRIES) {
			k_sleep(K_MSEC(CONFIG_LORA_STAR_TX_RETRY_BACKOFF_MS +
				       (sys_rand32_get() % CONFIG_LORA_STAR_TX_RETRY_BACKOFF_MS)));
		}
	}

	ls_unregister_frame_cb(ctx, ack_handler);

	if (!ctx->always_on_rx) {
		ls_mac_rx_stop(ctx);
	}

	return ret;
}

static void ls_tx_thread_fn(void *p1, void *p2, void *p3)
{
	struct ls_tx_cmd cmd;
	int ret;

	ARG_UNUSED(p1);
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	while (true) {
		k_msgq_get(&ls_tx_msgq, &cmd, K_FOREVER);

		if (cmd.fn) {
			ret = cmd.fn(cmd.ctx, cmd.user_data);
		} else if (cmd.want_ack) {
			ret = ls_send_data_ack(cmd.ctx, cmd.dst, cmd.data, cmd.len);
		} else {
			ret = ls_send_data(cmd.ctx, cmd.dst, cmd.data, cmd.len);
		}

		if (cmd.done_cb) {
			cmd.done_cb(ret, cmd.user_data);
		}
	}
}

static int ls_send_async_common(struct ls_ctx *ctx,
				uint16_t dst, const uint8_t *data, size_t len,
				ls_send_cb done_cb, void *user_data, bool want_ack)
{
	struct ls_tx_cmd cmd;

	if (!ctx || len > LS_MAX_PAYLOAD_SIZE || (len > 0 && !data)) {
		return -EINVAL;
	}

	cmd.ctx       = ctx;
	cmd.dst       = dst;
	cmd.want_ack  = want_ack;
	cmd.done_cb   = done_cb;
	cmd.user_data = user_data;
	cmd.len       = len;
	cmd.fn        = NULL;
	if (len > 0) {
		memcpy(cmd.data, data, len);
	}

	return k_msgq_put(&ls_tx_msgq, &cmd, K_NO_WAIT);
}

int ls_send_data_async(struct ls_ctx *ctx,
		       uint16_t dst, const uint8_t *data, size_t len,
		       ls_send_cb done_cb, void *user_data)
{
	return ls_send_async_common(ctx, dst, data, len, done_cb, user_data, false);
}

int ls_send_data_ack_async(struct ls_ctx *ctx,
			   uint16_t dst, const uint8_t *data, size_t len,
			   ls_send_cb done_cb, void *user_data)
{
	return ls_send_async_common(ctx, dst, data, len, done_cb, user_data, true);
}

int ls_tx_schedule(struct ls_ctx *ctx,
		   int (*fn)(struct ls_ctx *, void *), void *arg,
		   ls_send_cb done_cb)
{
	struct ls_tx_cmd cmd;

	if (!ctx || !fn) {
		return -EINVAL;
	}

	memset(&cmd, 0, sizeof(cmd));
	cmd.ctx       = ctx;
	cmd.fn        = fn;
	cmd.user_data = arg;
	cmd.done_cb   = done_cb;

	return k_msgq_put(&ls_tx_msgq, &cmd, K_NO_WAIT);
}
