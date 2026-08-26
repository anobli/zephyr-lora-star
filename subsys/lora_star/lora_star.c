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
#include "event.h"

LOG_MODULE_REGISTER(lora_star, CONFIG_LORA_STAR_LOG_LEVEL);

/* Guard for the peer's RX window and processing latency, beyond airtime. */
#define LS_DATA_ACK_PROC_GUARD_MS 1000U

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

K_MSGQ_DEFINE(ls_msgq, sizeof(struct ls_event), CONFIG_LORA_STAR_MSGQ_DEPTH, 4);

static struct k_timer ack_timer;
static struct k_timer backoff_timer;

static void ack_timer_cb(struct k_timer *timer)
{
	struct ls_event ev = {.type = LS_EVENT_TIMEOUT};

	ARG_UNUSED(timer);
	k_msgq_put(&ls_msgq, &ev, K_NO_WAIT);
}

static void backoff_timer_cb(struct k_timer *timer)
{
	struct ls_event ev = {.type = LS_EVENT_RETRY};

	ARG_UNUSED(timer);
	k_msgq_put(&ls_msgq, &ev, K_NO_WAIT);
}

/*
 * In-thread state tracking one in-flight TX that is waiting for a response.
 * Only one such TX can be pending at a time; the thread serialises all sends.
 */
struct ls_pending {
	bool       active;
	uint8_t    resp_type;
	uint16_t   resp_src;
	int        retries;
	uint32_t   timeout_ms;
	struct ls_event saved_tx;
};

static void ls_thread_fn(void *p1, void *p2, void *p3);

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

	ctx->radio_dev    = lora_dev;
	ctx->own_addr     = LS_COORD_ADDR;
	ctx->fcnt         = 0;
	ctx->always_on_rx = false;
	memset(ctx->network_key, 0, sizeof(ctx->network_key));
	memset(ctx->_handlers, 0, sizeof(ctx->_handlers));

	ctx->_msgq = &ls_msgq;
	k_mutex_init(&ctx->_handlers_lock);

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

/*
 * Dispatch a frame to all matching registered handlers.
 * Returns true if any handler returned a negative value (i.e., consumed the frame).
 */
static bool ls_dispatch_frame(struct ls_ctx *ctx, struct ls_frame *frame)
{
	bool consumed = false;
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
			consumed = true;
			break;
		}
	}

	k_mutex_unlock(&ctx->_handlers_lock);
	return consumed;
}

/* -------------------------------------------------------------------------
 * Thread event handlers
 * ------------------------------------------------------------------------- */

static void arm_timer(struct ls_pending *ps)
{
	k_timer_start(&ack_timer, K_MSEC(ps->timeout_ms), K_NO_WAIT);
}

static void pending_clear(struct ls_ctx *ctx, struct ls_pending *ps, int ret)
{
	ls_send_cb done_cb;
	void *user_data;

	ps->active = false;

	if (!ctx->always_on_rx) {
		ls_mac_rx_stop(ctx);
	}

	if (ps->saved_tx.type == LS_EVENT_TX_DATA) {
		done_cb   = ps->saved_tx.tx_data.done_cb;
		user_data = ps->saved_tx.tx_data.user_data;
	} else {
		done_cb   = ps->saved_tx.tx_raw.done_cb;
		user_data = ps->saved_tx.tx_raw.user_data;
	}

	if (done_cb) {
		done_cb(ret, user_data);
	}
}

static void handle_tx_data(struct ls_ctx *ctx, struct ls_pending *ps,
			   const struct ls_event *ev)
{
	struct ls_frame frame;
	int ret;

	ls_frame_init(&frame);
	ls_frame_set_type(&frame, LS_TYPE_DATA);
	ls_frame_set_dst(&frame, ev->tx_data.dst);
	ls_frame_set_flags(&frame, ev->tx_data.flags);
	if (ev->tx_data.payload_len > 0) {
		ret = ls_frame_set_payload(&frame, ev->tx_data.payload, ev->tx_data.payload_len);
		if (ret < 0) {
			if (ev->tx_data.done_cb) {
				ev->tx_data.done_cb(ret, ev->tx_data.user_data);
			}
			return;
		}
	}

	if (!ctx->always_on_rx) {
		ls_mac_rx_stop(ctx);
	}

	ret = ls_mac_send(ctx, &frame);

	if (ret < 0 || !ev->tx_data.want_ack) {
		if (ev->tx_data.done_cb) {
			ev->tx_data.done_cb(ret, ev->tx_data.user_data);
		}
		return;
	}

	if (!ctx->always_on_rx) {
		ls_mac_recv(ctx);
	}

	ps->active     = true;
	ps->resp_type  = LS_TYPE_ACK;
	ps->resp_src   = ev->tx_data.dst;
	ps->retries    = CONFIG_LORA_STAR_TX_MAX_RETRIES;
	ps->timeout_ms = ls_mac_airtime_ms(ctx, LS_FRAME_SIZE(ev->tx_data.payload_len))
			 + ls_mac_airtime_ms(ctx, LS_FRAME_SIZE(0))
			 + CONFIG_LORA_STAR_ACK_GUARD_MS + LS_DATA_ACK_PROC_GUARD_MS;
	ps->saved_tx   = *ev;

	arm_timer(ps);
}

static void handle_tx_raw(struct ls_ctx *ctx, struct ls_pending *ps,
			  const struct ls_event *ev)
{
	struct ls_frame frame;
	int ret;

	if (ev->tx_raw.buf_len > LS_MAX_FRAME_SIZE ||
	    ev->tx_raw.buf_len < LS_OVERHEAD_SIZE) {
		if (ev->tx_raw.done_cb) {
			ev->tx_raw.done_cb(-EINVAL, ev->tx_raw.user_data);
		}
		return;
	}

	ls_frame_init(&frame);
	frame.payload_len = ev->tx_raw.buf_len - LS_OVERHEAD_SIZE;
	memcpy(frame.buf, ev->tx_raw.buf, ev->tx_raw.buf_len);

	if (!ctx->always_on_rx) {
		ls_mac_rx_stop(ctx);
	}

	ret = ls_mac_send(ctx, &frame);

	if (ret < 0 || !ev->tx_raw.want_resp) {
		if (ev->tx_raw.done_cb) {
			ev->tx_raw.done_cb(ret, ev->tx_raw.user_data);
		}
		return;
	}

	if (!ctx->always_on_rx) {
		ls_mac_recv(ctx);
	}

	ps->active    = true;
	ps->resp_type = ev->tx_raw.resp_type;
	ps->resp_src  = ev->tx_raw.resp_src;
	ps->retries   = CONFIG_LORA_STAR_TX_MAX_RETRIES;
	ps->timeout_ms = ev->tx_raw.timeout_ms
			 ? ev->tx_raw.timeout_ms
			 : (ls_mac_airtime_ms(ctx, LS_MAX_FRAME_SIZE)
			    + CONFIG_LORA_STAR_ACK_GUARD_MS);
	ps->saved_tx  = *ev;

	arm_timer(ps);
}

static void handle_rx(struct ls_ctx *ctx, struct ls_pending *ps,
		      struct ls_event *ev)
{
	struct ls_frame *frame = &ev->rx;
	uint8_t frame_type     = ls_frame_get_type(frame);
	uint16_t frame_src     = ls_frame_get_src(frame);
	bool matched           = false;
	bool consumed;

	if (ps->active &&
	    frame_type == ps->resp_type &&
	    (ps->resp_src == LS_BCAST_ADDR || frame_src == ps->resp_src)) {
		k_timer_stop(&ack_timer);
		matched = true;
	}

	consumed = ls_dispatch_frame(ctx, frame);

	if (!matched) {
		return;
	}

	/*
	 * For DATA/ACK responses the MAC already verified the MIC, so a match
	 * is always valid.  For raw responses (e.g. JOIN_ACCEPT) the dispatch
	 * handler verifies the pairing MIC; if it returns false (not consumed)
	 * the frame was rejected and we keep waiting.
	 */
	if (ps->saved_tx.type == LS_EVENT_TX_DATA || consumed) {
		pending_clear(ctx, ps, 0);
	} else {
		/* Not consumed — MIC mismatch or wrong network; keep waiting. */
		arm_timer(ps);
	}
}

static void handle_timeout(struct ls_ctx *ctx, struct ls_pending *ps)
{
	uint32_t jitter;

	if (!ps->active) {
		return;
	}

	if (ps->retries > 0) {
		ps->retries--;
		ps->active = false;

		if (!ctx->always_on_rx) {
			ls_mac_rx_stop(ctx);
		}

		sys_rand_get(&jitter, sizeof(jitter));
		k_timer_start(&backoff_timer,
			      K_MSEC(CONFIG_LORA_STAR_TX_RETRY_BACKOFF_MS +
				     (jitter % CONFIG_LORA_STAR_TX_RETRY_BACKOFF_MS)),
			      K_NO_WAIT);
		return;
	}

	pending_clear(ctx, ps, -ETIMEDOUT);
}

static void handle_retry(struct ls_ctx *ctx, struct ls_pending *ps)
{
	int remaining = ps->retries;

	if (ps->saved_tx.type == LS_EVENT_TX_DATA) {
		handle_tx_data(ctx, ps, &ps->saved_tx);
	} else {
		handle_tx_raw(ctx, ps, &ps->saved_tx);
	}
	if (ps->active) {
		ps->retries = remaining;
	}
}

static void ls_thread_fn(void *p1, void *p2, void *p3)
{
	struct ls_ctx *ctx = p1;
	struct ls_pending pending = {0};
	struct ls_event ev;

	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	k_timer_init(&ack_timer, ack_timer_cb, NULL);
	k_timer_init(&backoff_timer, backoff_timer_cb, NULL);

	LOG_INF("LoRa Star thread started");

	while (true) {
		k_msgq_get(&ls_msgq, &ev, K_FOREVER);

		switch (ev.type) {
		case LS_EVENT_TX_DATA:
			handle_tx_data(ctx, &pending, &ev);
			break;
		case LS_EVENT_TX_RAW:
			handle_tx_raw(ctx, &pending, &ev);
			break;
		case LS_EVENT_RX:
			handle_rx(ctx, &pending, &ev);
			break;
		case LS_EVENT_TIMEOUT:
			handle_timeout(ctx, &pending);
			break;
		case LS_EVENT_RETRY:
			handle_retry(ctx, &pending);
			break;
		}
	}
}

/* -------------------------------------------------------------------------
 * Public send API
 * ------------------------------------------------------------------------- */

int ls_send_ack(struct ls_ctx *ctx, uint16_t dst)
{
	struct ls_frame frame;

	ls_frame_init(&frame);
	ls_frame_set_type(&frame, LS_TYPE_ACK);
	ls_frame_set_dst(&frame, dst);
	ls_frame_set_flags(&frame, 0);

	return ls_mac_send(ctx, &frame);
}

/*
 * Synchronous-wait helper used by the blocking send variants.
 * Must NOT be called from the LoRa Star thread itself.
 */
struct ls_sync_wait {
	struct k_sem sem;
	int          ret;
};

static void sync_done_cb(int ret, void *user_data)
{
	struct ls_sync_wait *w = user_data;

	w->ret = ret;
	k_sem_give(&w->sem);
}

static int sync_send(int enqueue_ret, struct ls_sync_wait *w)
{
	if (enqueue_ret < 0) {
		return enqueue_ret;
	}
	k_sem_take(&w->sem, K_FOREVER);
	return w->ret;
}

int ls_send_data(struct ls_ctx *ctx, uint16_t dst, const uint8_t *data, size_t len)
{
	struct ls_sync_wait w;

	k_sem_init(&w.sem, 0, 1);
	return sync_send(ls_send_data_async(ctx, dst, data, len, sync_done_cb, &w), &w);
}

int ls_send_data_ack(struct ls_ctx *ctx, uint16_t dst, const uint8_t *data, size_t len)
{
	struct ls_sync_wait w;

	k_sem_init(&w.sem, 0, 1);
	return sync_send(ls_send_data_ack_async(ctx, dst, data, len, sync_done_cb, &w), &w);
}

static int enqueue_tx_data(struct ls_ctx *ctx,
			   uint16_t dst, const uint8_t *data, size_t len,
			   uint8_t flags, bool want_ack,
			   ls_send_cb done_cb, void *user_data)
{
	struct ls_event ev;

	if (!ctx || len > LS_MAX_PAYLOAD_SIZE || (len > 0 && !data)) {
		return -EINVAL;
	}

	ev.type                = LS_EVENT_TX_DATA;
	ev.tx_data.dst         = dst;
	ev.tx_data.payload_len = len;
	ev.tx_data.flags       = flags;
	ev.tx_data.want_ack    = want_ack;
	ev.tx_data.done_cb     = done_cb;
	ev.tx_data.user_data   = user_data;
	if (len > 0) {
		memcpy(ev.tx_data.payload, data, len);
	}

	return k_msgq_put(&ls_msgq, &ev, K_NO_WAIT);
}

int ls_send_data_async(struct ls_ctx *ctx,
		       uint16_t dst, const uint8_t *data, size_t len,
		       ls_send_cb done_cb, void *user_data)
{
	return enqueue_tx_data(ctx, dst, data, len, 0, false, done_cb, user_data);
}

int ls_send_data_ack_async(struct ls_ctx *ctx,
			   uint16_t dst, const uint8_t *data, size_t len,
			   ls_send_cb done_cb, void *user_data)
{
	return enqueue_tx_data(ctx, dst, data, len, LS_FLAG_ACK_REQ, true,
			       done_cb, user_data);
}

int ls_send_raw_async(struct ls_ctx *ctx,
		      const uint8_t *buf, size_t len,
		      bool want_resp, uint8_t resp_type, uint16_t resp_src,
		      uint32_t timeout_ms,
		      ls_send_cb done_cb, void *user_data)
{
	struct ls_event ev;

	if (!ctx || !buf || len == 0 || len > LS_MAX_FRAME_SIZE) {
		return -EINVAL;
	}

	ev.type             = LS_EVENT_TX_RAW;
	ev.tx_raw.buf_len   = len;
	ev.tx_raw.want_resp = want_resp;
	ev.tx_raw.resp_type = resp_type;
	ev.tx_raw.resp_src  = resp_src;
	ev.tx_raw.timeout_ms = timeout_ms;
	ev.tx_raw.done_cb   = done_cb;
	ev.tx_raw.user_data = user_data;
	memcpy(ev.tx_raw.buf, buf, len);

	return k_msgq_put(&ls_msgq, &ev, K_NO_WAIT);
}
