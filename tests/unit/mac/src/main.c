/*
 * Copyright (c) 2026 Alexandre Bailon <abailon@baylibre.com>
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/ztest.h>
#include <string.h>
#include <zephyr/drivers/lora.h>
#include <zephyr/drivers/lora_fake.h>
#include <lora_star/mac.h>

#include "event.h"

static uint8_t test_buf[64] = {
	0x12, 0x45, 0x11, 0x74,
};

static struct ls_ctx ctx;
static struct ls_event test_msgq_buf[CONFIG_LORA_STAR_MSGQ_DEPTH];
static struct k_msgq test_msgq;

static void mac_before(void *fixture)
{
	ARG_UNUSED(fixture);
	lora_fake_reset();
	memset(&ctx, 0, sizeof(ctx));
	ctx.radio_dev = lora_fake_get_device();
	k_msgq_init(&test_msgq, (char *)test_msgq_buf, sizeof(struct ls_event),
		     CONFIG_LORA_STAR_MSGQ_DEPTH);
	ctx._msgq = &test_msgq;
	k_mutex_init(&ctx._handlers_lock);
}

/* --------------------------------------------------------------------------
 * ls_mac_init
 * -------------------------------------------------------------------------- */

ZTEST(lora_star_mac, test_ls_mac_init)
{
	int ret;

	ret = ls_mac_init(&ctx);

	zassert_equal(ret, 0);
	zassert_equal(lora_fake_config_fake.call_count, 1);
}

/* --------------------------------------------------------------------------
 * ls_mac_send
 * -------------------------------------------------------------------------- */

ZTEST(lora_star_mac, test_ls_mac_send)
{
	struct ls_frame frame = {
		.payload_len = 0,
	};
	const uint8_t *sent_data;
	uint32_t sent_data_len;
	int ret;

	ret = ls_mac_send(&ctx, &frame, NULL);
	sent_data = lora_fake_get_sent_data(&sent_data_len);

	zassert_equal(ret, 0);
	zassert_equal(sent_data_len, LS_FRAME_SIZE(frame.payload_len));
	zassert_mem_equal(sent_data, frame.buf, sent_data_len);
}

ZTEST(lora_star_mac, test_ls_mac_send_null_ctx)
{
	int ret;

	ret = ls_mac_send(NULL, NULL, NULL);

	zassert_equal(ret, -ENODEV);
}

ZTEST(lora_star_mac, test_ls_mac_send_null_device)
{
	struct ls_ctx no_dev_ctx = { .radio_dev = NULL };
	int ret;

	ret = ls_mac_send(&no_dev_ctx, NULL, NULL);

	zassert_equal(ret, -ENODEV);
}

ZTEST(lora_star_mac, test_ls_mac_send_null_frame)
{
	int ret;

	ret = ls_mac_send(&ctx, NULL, NULL);

	zassert_equal(ret, -EINVAL);
}

/* --------------------------------------------------------------------------
 * ls_mac_recv / ls_mac_rx_stop
 * -------------------------------------------------------------------------- */

ZTEST(lora_star_mac, test_ls_mac_recv_null_ctx)
{
	int ret;

	ret = ls_mac_recv(NULL);

	zassert_equal(ret, -ENODEV);
}

ZTEST(lora_star_mac, test_ls_mac_recv_null_device)
{
	struct ls_ctx no_dev_ctx = { .radio_dev = NULL };
	int ret;

	ret = ls_mac_recv(&no_dev_ctx);

	zassert_equal(ret, -ENODEV);
}

ZTEST(lora_star_mac, test_ls_mac_recv)
{
	struct ls_event ev;
	int ret;

	ret = ls_mac_recv(&ctx);
	zassert_equal(ret, 0);
	lora_fake_set_recv_data(test_buf, sizeof(test_buf), -70, 5);
	lora_fake_trigger_recv_async();
	ret = k_msgq_get(ctx._msgq, &ev, K_NO_WAIT);

	zassert_equal(ret, 0);
	zassert_equal(ev.type, LS_EVENT_RX);
	zassert_equal(LS_FRAME_SIZE(ev.rx.payload_len), sizeof(test_buf));
	zassert_mem_equal(ev.rx.buf, test_buf, sizeof(test_buf));
}

ZTEST(lora_star_mac, test_ls_mac_rx_stop_null_ctx)
{
	int ret;

	ret = ls_mac_rx_stop(NULL);

	zassert_equal(ret, -ENODEV);
}

ZTEST(lora_star_mac, test_ls_mac_rx_stop_null_device)
{
	struct ls_ctx no_dev_ctx = { .radio_dev = NULL };
	int ret;

	ret = ls_mac_rx_stop(&no_dev_ctx);

	zassert_equal(ret, -ENODEV);
}

ZTEST(lora_star_mac, test_ls_mac_rx_stop)
{
	struct ls_event ev;
	int ret;

	ls_mac_recv(&ctx);
	ls_mac_rx_stop(&ctx);
	k_msgq_purge(ctx._msgq);
	lora_fake_set_recv_data(test_buf, sizeof(test_buf), -70, 5);
	lora_fake_trigger_recv_async();
	ret = k_msgq_get(ctx._msgq, &ev, K_NO_WAIT);

	zassert_equal(ret, -ENOMSG);
}

/* --------------------------------------------------------------------------
 * ls_mac_airtime_ms
 * -------------------------------------------------------------------------- */

ZTEST(lora_star_mac, test_ls_mac_airtime_ms)
{
	uint32_t airtime;

	lora_fake_airtime_fake.return_val = 100;
	airtime = ls_mac_airtime_ms(&ctx, 64);

	zassert_equal(airtime, 100);
	zassert_equal(lora_fake_airtime_fake.arg1_val, 64);
}

ZTEST_SUITE(lora_star_mac, NULL, NULL, mac_before, NULL, NULL);
