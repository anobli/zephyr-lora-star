/*
 * Copyright (c) 2026 Alexandre Bailon <abailon@baylibre.com>
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/ztest.h>
#include <zephyr/drivers/lora.h>
#include <zephyr/drivers/lora_fake.h>

#include <lora_star/lora_star.h>
#include <lora_star/mac.h>
#include <lora_star/frame.h>
#include <lora_star/crypto.h>

#include "event.h"

/* --------------------------------------------------------------------------
 * Shared state
 * -------------------------------------------------------------------------- */

static struct ls_ctx *g_ctx;

static const uint8_t test_network_key[LS_NETWORK_KEY_SIZE] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
};

/* --------------------------------------------------------------------------
 * Callbacks used across dispatch tests
 * -------------------------------------------------------------------------- */

static struct k_sem g_cb_sem;
static uint8_t  g_last_type;
static uint16_t g_last_src;
static uint16_t g_last_dst;

static int record_frame_cb(struct ls_ctx *ctx, struct ls_frame *frame, void *user_data)
{
	ARG_UNUSED(ctx);
	ARG_UNUSED(user_data);
	g_last_type = ls_frame_get_type(frame);
	g_last_src  = ls_frame_get_src(frame);
	g_last_dst  = ls_frame_get_dst(frame);
	k_sem_give(&g_cb_sem);
	return 0;
}

static int stop_dispatch_cb(struct ls_ctx *ctx, struct ls_frame *frame, void *user_data)
{
	ARG_UNUSED(ctx);
	ARG_UNUSED(user_data);
	g_last_type = ls_frame_get_type(frame);
	k_sem_give(&g_cb_sem);
	return -1;
}

static int never_called_cb(struct ls_ctx *ctx, struct ls_frame *frame, void *user_data)
{
	ARG_UNUSED(ctx);
	ARG_UNUSED(frame);
	ARG_UNUSED(user_data);
	zassert_unreachable("this callback must not be invoked");
	return 0;
}

static int dummy_cb(struct ls_ctx *ctx, struct ls_frame *frame, void *user_data)
{
	ARG_UNUSED(ctx);
	ARG_UNUSED(frame);
	ARG_UNUSED(user_data);
	return 0;
}

/* --------------------------------------------------------------------------
 * Helpers
 * -------------------------------------------------------------------------- */

/*
 * Push a frame as an LS_EVENT_RX directly into the LS dispatch queue,
 * bypassing the MAC/radio layers.
 */
static void push_frame(struct ls_ctx *ctx, uint8_t type, uint16_t src, uint16_t dst)
{
	struct ls_event ev;
	int ret;

	ev.type = LS_EVENT_RX;
	ls_frame_init(&ev.rx);
	ls_frame_set_type(&ev.rx, type);
	ls_frame_set_src(&ev.rx, src);
	ls_frame_set_dst(&ev.rx, dst);
	ls_frame_set_fcnt(&ev.rx, 0);
	ls_frame_set_flags(&ev.rx, 0);
	ret = k_msgq_put(ctx->_msgq, &ev, K_MSEC(100));
	zassert_equal(ret, 0, "k_msgq_put failed: %d", ret);
}

/* --------------------------------------------------------------------------
 * Suite setup (runs once per suite, g_ctx is a singleton)
 * -------------------------------------------------------------------------- */

static void *suite_setup(void)
{
	if (!g_ctx) {
		g_ctx = ls_init(lora_fake_get_device());
		zassert_not_null(g_ctx, "ls_init failed");
	}
	return NULL;
}

/* --------------------------------------------------------------------------
 * Suite 1: lora_star_init
 * Covers ls_init, ls_is_paired, ls_set_network_key, ls_set_own_addr.
 * -------------------------------------------------------------------------- */

static void init_before(void *fixture)
{
	static const uint8_t zero[LS_NETWORK_KEY_SIZE] = {0};

	ARG_UNUSED(fixture);
	ls_set_own_addr(g_ctx, LS_COORD_ADDR);
	ls_set_network_key(g_ctx, zero);
	g_ctx->fcnt = 0;
}

ZTEST(lora_star_init, test_init_null_device)
{
	struct ls_ctx *ctx;

	ctx = ls_init(NULL);

	zassert_is_null(ctx, "ls_init(NULL) must return NULL");
}

ZTEST(lora_star_init, test_is_paired_freshly_init)
{
	zassert_false(ls_is_paired(g_ctx),
		      "freshly-initialised context must not be paired");
}

ZTEST(lora_star_init, test_is_paired_addr_only)
{
	ls_set_own_addr(g_ctx, 0x0001);

	zassert_false(ls_is_paired(g_ctx),
		      "non-zero addr with all-zero key must not be paired");
}

ZTEST(lora_star_init, test_is_paired_key_only)
{
	ls_set_network_key(g_ctx, test_network_key);

	/* addr is still LS_COORD_ADDR from init_before */
	zassert_false(ls_is_paired(g_ctx),
		      "non-zero key with coordinator addr must not be paired");
}

ZTEST(lora_star_init, test_is_paired_both)
{
	ls_set_own_addr(g_ctx, 0x0001);
	ls_set_network_key(g_ctx, test_network_key);

	zassert_true(ls_is_paired(g_ctx),
		     "non-zero key and non-coordinator addr must be paired");
}

ZTEST(lora_star_init, test_set_own_addr)
{
	ls_set_own_addr(g_ctx, 0x0042);

	zassert_equal(g_ctx->own_addr, 0x0042);
}

ZTEST(lora_star_init, test_set_network_key)
{
	ls_set_network_key(g_ctx, test_network_key);

	zassert_mem_equal(g_ctx->network_key, test_network_key, LS_NETWORK_KEY_SIZE);
}

ZTEST_SUITE(lora_star_init, NULL, suite_setup, init_before, NULL, NULL);

/* --------------------------------------------------------------------------
 * Suite 2: lora_star_callbacks
 * Covers ls_register_frame_cb, ls_register_data_cb, ls_unregister_frame_cb,
 * and the frame dispatch logic.
 * -------------------------------------------------------------------------- */

static void callbacks_before(void *fixture)
{
	int i;

	ARG_UNUSED(fixture);

	k_mutex_lock(&g_ctx->_handlers_lock, K_FOREVER);
	for (i = 0; i < CONFIG_LORA_STAR_MAX_FRAME_CBS; i++) {
		g_ctx->_handlers[i].cb = NULL;
	}
	k_mutex_unlock(&g_ctx->_handlers_lock);

	k_sem_init(&g_cb_sem, 0, 1);
	g_last_type = 0;
	g_last_src  = 0;
	g_last_dst  = 0;
}

ZTEST(lora_star_callbacks, test_register_cb_success)
{
	struct ls_frame_filter filter = {
		.type = LS_TYPE_DATA,
		.src  = LS_BCAST_ADDR,
		.dst  = LS_BCAST_ADDR,
	};
	struct ls_frame_handler *hdl;

	hdl = ls_register_frame_cb(g_ctx, &filter, dummy_cb, NULL);

	zassert_not_null(hdl, "registration into an empty registry must succeed");
}

ZTEST(lora_star_callbacks, test_register_cb_full)
{
	struct ls_frame_filter filter = {
		.type = 0,
		.src  = LS_BCAST_ADDR,
		.dst  = LS_BCAST_ADDR,
	};
	struct ls_frame_handler *hdl;
	int i;

	for (i = 0; i < CONFIG_LORA_STAR_MAX_FRAME_CBS; i++) {
		hdl = ls_register_frame_cb(g_ctx, &filter, dummy_cb, NULL);
		zassert_not_null(hdl, "registration %d should succeed", i);
	}

	hdl = ls_register_frame_cb(g_ctx, &filter, dummy_cb, NULL);

	zassert_is_null(hdl, "registration into a full registry must return NULL");
}

ZTEST(lora_star_callbacks, test_register_after_unregister)
{
	struct ls_frame_filter filter = {
		.type = 0,
		.src  = LS_BCAST_ADDR,
		.dst  = LS_BCAST_ADDR,
	};
	struct ls_frame_handler *hdl;
	int i;

	for (i = 0; i < CONFIG_LORA_STAR_MAX_FRAME_CBS; i++) {
		hdl = ls_register_frame_cb(g_ctx, &filter, dummy_cb, NULL);
		zassert_not_null(hdl);
	}

	ls_unregister_frame_cb(g_ctx, hdl);

	hdl = ls_register_frame_cb(g_ctx, &filter, dummy_cb, NULL);
	zassert_not_null(hdl, "freed slot must be reusable");
}

ZTEST(lora_star_callbacks, test_unregister_null_safe)
{
	ls_unregister_frame_cb(g_ctx, NULL);
	/* no crash or assertion — test passes if we reach here */
}

ZTEST(lora_star_callbacks, test_register_data_cb_filter)
{
	struct ls_frame_handler *hdl;

	hdl = ls_register_data_cb(g_ctx, 0x0005, dummy_cb, NULL);
	zassert_not_null(hdl);

	zassert_equal(hdl->filter.type, LS_TYPE_DATA);
	zassert_equal(hdl->filter.src,  LS_BCAST_ADDR);
	zassert_equal(hdl->filter.dst,  0x0005);
}

ZTEST(lora_star_callbacks, test_dispatch_type_match)
{
	struct ls_frame_filter filter = {
		.type = LS_TYPE_JOIN_REQ,
		.src  = LS_BCAST_ADDR,
		.dst  = LS_BCAST_ADDR,
	};
	struct ls_frame_handler *hdl;
	int ret;

	hdl = ls_register_frame_cb(g_ctx, &filter, record_frame_cb, NULL);
	zassert_not_null(hdl);

	push_frame(g_ctx, LS_TYPE_JOIN_REQ, 0x0001, LS_COORD_ADDR);
	ret = k_sem_take(&g_cb_sem, K_MSEC(500));

	zassert_equal(ret, 0, "callback must fire for matching type");
	zassert_equal(g_last_type, LS_TYPE_JOIN_REQ);
}

ZTEST(lora_star_callbacks, test_dispatch_type_wildcard)
{
	struct ls_frame_filter filter = {
		.type = 0,
		.src  = LS_BCAST_ADDR,
		.dst  = LS_BCAST_ADDR,
	};
	struct ls_frame_handler *hdl;
	int ret;

	hdl = ls_register_frame_cb(g_ctx, &filter, record_frame_cb, NULL);
	zassert_not_null(hdl);

	push_frame(g_ctx, LS_TYPE_JOIN_ACCEPT, 0x0001, LS_COORD_ADDR);
	ret = k_sem_take(&g_cb_sem, K_MSEC(500));

	zassert_equal(ret, 0, "wildcard-type handler must fire for any frame type");
}

ZTEST(lora_star_callbacks, test_dispatch_src_match)
{
	struct ls_frame_filter filter = {
		.type = 0,
		.src  = 0x0002,
		.dst  = LS_BCAST_ADDR,
	};
	struct ls_frame_handler *hdl;
	int ret;

	hdl = ls_register_frame_cb(g_ctx, &filter, record_frame_cb, NULL);
	zassert_not_null(hdl);

	push_frame(g_ctx, LS_TYPE_JOIN_REQ, 0x0002, LS_COORD_ADDR);
	ret = k_sem_take(&g_cb_sem, K_MSEC(500));

	zassert_equal(ret, 0, "callback must fire for matching src");
	zassert_equal(g_last_src, 0x0002);
}

ZTEST(lora_star_callbacks, test_dispatch_dst_match)
{
	struct ls_frame_filter filter = {
		.type = 0,
		.src  = LS_BCAST_ADDR,
		.dst  = 0x0003,
	};
	struct ls_frame_handler *hdl;
	int ret;

	hdl = ls_register_frame_cb(g_ctx, &filter, record_frame_cb, NULL);
	zassert_not_null(hdl);

	push_frame(g_ctx, LS_TYPE_JOIN_REQ, 0x0001, 0x0003);
	ret = k_sem_take(&g_cb_sem, K_MSEC(500));

	zassert_equal(ret, 0, "callback must fire for matching dst");
	zassert_equal(g_last_dst, 0x0003);
}

ZTEST(lora_star_callbacks, test_dispatch_no_match_type)
{
	struct ls_frame_filter filter = {
		.type = LS_TYPE_DATA,
		.src  = LS_BCAST_ADDR,
		.dst  = LS_BCAST_ADDR,
	};
	struct ls_frame_handler *hdl;
	int ret;

	hdl = ls_register_frame_cb(g_ctx, &filter, record_frame_cb, NULL);
	zassert_not_null(hdl);

	push_frame(g_ctx, LS_TYPE_JOIN_REQ, 0x0001, LS_COORD_ADDR);
	ret = k_sem_take(&g_cb_sem, K_MSEC(200));

	zassert_equal(ret, -EAGAIN, "callback must not fire when type does not match");
}

ZTEST(lora_star_callbacks, test_dispatch_no_match_src)
{
	struct ls_frame_filter filter = {
		.type = 0,
		.src  = 0x0010,
		.dst  = LS_BCAST_ADDR,
	};
	struct ls_frame_handler *hdl;
	int ret;

	hdl = ls_register_frame_cb(g_ctx, &filter, record_frame_cb, NULL);
	zassert_not_null(hdl);

	push_frame(g_ctx, LS_TYPE_JOIN_REQ, 0x0001, LS_COORD_ADDR);
	ret = k_sem_take(&g_cb_sem, K_MSEC(200));

	zassert_equal(ret, -EAGAIN, "callback must not fire when src does not match");
}

ZTEST(lora_star_callbacks, test_dispatch_no_match_dst)
{
	struct ls_frame_filter filter = {
		.type = 0,
		.src  = LS_BCAST_ADDR,
		.dst  = 0x0010,
	};
	struct ls_frame_handler *hdl;
	int ret;

	hdl = ls_register_frame_cb(g_ctx, &filter, record_frame_cb, NULL);
	zassert_not_null(hdl);

	push_frame(g_ctx, LS_TYPE_JOIN_REQ, 0x0001, LS_COORD_ADDR);
	ret = k_sem_take(&g_cb_sem, K_MSEC(200));

	zassert_equal(ret, -EAGAIN, "callback must not fire when dst does not match");
}

ZTEST(lora_star_callbacks, test_dispatch_stop_on_negative)
{
	struct ls_frame_filter filter = {
		.type = 0,
		.src  = LS_BCAST_ADDR,
		.dst  = LS_BCAST_ADDR,
	};
	struct ls_frame_handler *hdl1;
	struct ls_frame_handler *hdl2;
	int ret;

	/*
	 * Register stop_dispatch_cb first so it occupies the lower-indexed
	 * slot and is invoked before never_called_cb.
	 */
	hdl1 = ls_register_frame_cb(g_ctx, &filter, stop_dispatch_cb,  NULL);
	hdl2 = ls_register_frame_cb(g_ctx, &filter, never_called_cb,   NULL);
	zassert_not_null(hdl1);
	zassert_not_null(hdl2);

	push_frame(g_ctx, LS_TYPE_JOIN_REQ, 0x0001, LS_COORD_ADDR);
	ret = k_sem_take(&g_cb_sem, K_MSEC(500));

	/* If never_called_cb fires, it calls zassert_unreachable. */
	zassert_equal(ret, 0, "first handler must be invoked");
}

ZTEST_SUITE(lora_star_callbacks, NULL, suite_setup, callbacks_before, NULL, NULL);

/* --------------------------------------------------------------------------
 * Suite 3: lora_star_send
 * Covers ls_send_ack, ls_send_data, ls_send_data_ack.
 * -------------------------------------------------------------------------- */

static void send_before(void *fixture)
{
	ARG_UNUSED(fixture);
	lora_fake_reset();
	ls_set_own_addr(g_ctx, 0x0001);
	ls_set_network_key(g_ctx, test_network_key);
	g_ctx->fcnt = 0;
	g_ctx->always_on_rx = false;

	/* clear any registered handlers */
	k_mutex_lock(&g_ctx->_handlers_lock, K_FOREVER);
	memset(g_ctx->_handlers, 0, sizeof(g_ctx->_handlers));
	k_mutex_unlock(&g_ctx->_handlers_lock);
}

ZTEST(lora_star_send, test_send_ack_ok)
{
	int ret;

	ret = ls_send_ack(g_ctx, LS_COORD_ADDR);

	zassert_equal(ret, 0);
}

ZTEST(lora_star_send, test_send_ack_frame_type_and_size)
{
	const uint8_t *sent;
	uint32_t sent_len;

	ls_send_ack(g_ctx, LS_COORD_ADDR);
	sent = lora_fake_get_sent_data(&sent_len);

	zassert_equal(sent_len, LS_FRAME_SIZE(0),
		      "ACK frame size must be LS_FRAME_SIZE(0), got %u", sent_len);
	zassert_equal(sent[0], LS_TYPE_ACK,
		      "first byte must be LS_TYPE_ACK, got 0x%02x", sent[0]);
}

ZTEST(lora_star_send, test_send_data_ok)
{
	static const uint8_t payload[] = {0xDE, 0xAD, 0xBE, 0xEF};
	int ret;

	ret = ls_send_data(g_ctx, LS_COORD_ADDR, payload, sizeof(payload));

	zassert_equal(ret, 0);
}

ZTEST(lora_star_send, test_send_data_frame_type_and_size)
{
	static const uint8_t payload[] = {0x01, 0x02, 0x03};
	const uint8_t *sent;
	uint32_t sent_len;

	ls_send_data(g_ctx, LS_COORD_ADDR, payload, sizeof(payload));
	sent = lora_fake_get_sent_data(&sent_len);

	zassert_equal(sent_len, LS_FRAME_SIZE(sizeof(payload)),
		      "DATA frame size mismatch: got %u, expected %zu",
		      sent_len, LS_FRAME_SIZE(sizeof(payload)));
	zassert_equal(sent[0], LS_TYPE_DATA,
		      "first byte must be LS_TYPE_DATA, got 0x%02x", sent[0]);
}

ZTEST(lora_star_send, test_send_data_ack_timeout)
{
	static const uint8_t payload[] = {0xAB};
	int ret;

	/* No ACK injected — must time out after all retries are exhausted. */
	ret = ls_send_data_ack(g_ctx, LS_COORD_ADDR, payload, sizeof(payload));

	zassert_equal(ret, -ETIMEDOUT,
		      "ls_send_data_ack must return -ETIMEDOUT with no ACK, got %d", ret);
}

/* Thread context for test_send_data_ack_success */

static K_THREAD_STACK_DEFINE(ack_thread_stack, 4096);
static struct k_thread ack_thread;
static int             ack_thread_ret;

struct ack_send_args {
	struct ls_ctx  *ctx;
	uint16_t        dst;
};

static void ack_send_fn(void *p1, void *p2, void *p3)
{
	struct ack_send_args *args = p1;
	static const uint8_t payload[] = {0xCA, 0xFE};

	ARG_UNUSED(p2);
	ARG_UNUSED(p3);
	ack_thread_ret = ls_send_data_ack(args->ctx, args->dst, payload, sizeof(payload));
}

ZTEST(lora_star_send, test_send_data_ack_success)
{
	struct ack_send_args args;
	struct ls_frame ack_frame;
	int ret;

	/*
	 * Build a valid ACK frame (src=coordinator, dst=our node address)
	 * encrypted and signed with the test network key so it passes the
	 * MAC layer's signature check in mac_recv_cb.
	 */
	ls_frame_init(&ack_frame);
	ls_frame_set_type(&ack_frame,  LS_TYPE_ACK);
	ls_frame_set_src(&ack_frame,   LS_COORD_ADDR);
	ls_frame_set_dst(&ack_frame,   g_ctx->own_addr);
	ls_frame_set_fcnt(&ack_frame,  1);
	ls_frame_set_flags(&ack_frame, 0);
	ret = ls_frame_encrypt(&ack_frame, g_ctx->network_key);
	zassert_equal(ret, 0, "ls_frame_encrypt failed: %d", ret);
	ret = ls_frame_sign(&ack_frame, g_ctx->network_key);
	zassert_equal(ret, 0, "ls_frame_sign failed: %d", ret);

	/* Stage the ACK in lora_fake — delivered when lora_fake_trigger_recv_async is called. */
	lora_fake_set_recv_data(ack_frame.buf, LS_FRAME_SIZE(0), -50, 5);

	args.ctx = g_ctx;
	args.dst = LS_COORD_ADDR;
	k_thread_create(&ack_thread, ack_thread_stack,
			K_THREAD_STACK_SIZEOF(ack_thread_stack),
			ack_send_fn, &args, NULL, NULL,
			K_PRIO_PREEMPT(CONFIG_LORA_STAR_THREAD_PRIORITY), 0, K_NO_WAIT);

	/*
	 * Yield to let the helper thread run ls_send_data_ack through its
	 * internal ls_mac_recv() call, placing it into the RX-wait state.
	 */
	k_msleep(50);

	lora_fake_trigger_recv_async();

	ret = k_thread_join(&ack_thread, K_SECONDS(5));
	zassert_equal(ret, 0, "helper thread did not finish: %d", ret);
	zassert_equal(ack_thread_ret, 0,
		      "ls_send_data_ack must return 0 on ACK receipt, got %d", ack_thread_ret);
}

ZTEST_SUITE(lora_star_send, NULL, suite_setup, send_before, NULL, NULL);
