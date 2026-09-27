/*
 * Copyright (c) 2026 Alexandre Bailon <abailon@baylibre.com>
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/drivers/lora_fake.h>

#include <string.h>
#include <zephyr/device.h>

#define DT_DRV_COMPAT zephyr_lora_fake

DEFINE_FFF_GLOBALS;

DEFINE_FAKE_VALUE_FUNC(int, lora_fake_config,
		       const struct device *, const struct lora_modem_config *);

DEFINE_FAKE_VALUE_FUNC(uint32_t, lora_fake_airtime,
		       const struct device *, uint32_t);

DEFINE_FAKE_VALUE_FUNC(int, lora_fake_send,
		       const struct device *, uint8_t *, uint32_t);

DEFINE_FAKE_VALUE_FUNC(int, lora_fake_send_async,
		       const struct device *, uint8_t *, uint32_t,
		       struct k_poll_signal *);

DEFINE_FAKE_VALUE_FUNC(int, lora_fake_recv,
		       const struct device *, uint8_t *, uint8_t,
		       k_timeout_t, int16_t *, int8_t *);

DEFINE_FAKE_VALUE_FUNC(int, lora_fake_recv_async,
		       const struct device *, lora_recv_cb, void *);

DEFINE_FAKE_VALUE_FUNC(int, lora_fake_cad,
		       const struct device *, k_timeout_t);

DEFINE_FAKE_VALUE_FUNC(int, lora_fake_cad_async,
		       const struct device *, lora_cad_cb, void *);

/* --------------------------------------------------------------------------
 * Staged state
 * -------------------------------------------------------------------------- */

#define LORA_FAKE_BUF_SIZE 255

static struct {
	uint8_t  data[LORA_FAKE_BUF_SIZE];
	uint8_t  len;
	int16_t  rssi;
	int8_t   snr;
} staged_recv;

static struct {
	uint8_t  data[LORA_FAKE_BUF_SIZE];
	uint32_t len;
} staged_send;

static struct {
	lora_recv_cb cb;
	void        *user_data;
} current_rx;

/* --------------------------------------------------------------------------
 * Custom fake implementations
 * -------------------------------------------------------------------------- */

static int recv_async_custom(const struct device *dev, lora_recv_cb cb, void *user_data)
{
	ARG_UNUSED(dev);
	current_rx.cb        = cb;
	current_rx.user_data = user_data;
	return 0;
}

static int recv_custom(const struct device *dev, uint8_t *data, uint8_t size,
		       k_timeout_t timeout, int16_t *rssi, int8_t *snr)
{
	uint8_t n = MIN(staged_recv.len, size);

	memcpy(data, staged_recv.data, n);
	if (rssi) {
		*rssi = staged_recv.rssi;
	}
	if (snr) {
		*snr = staged_recv.snr;
	}
	return n;
}

static int send_custom(const struct device *dev, uint8_t *data, uint32_t len)
{
	uint32_t n = MIN(len, LORA_FAKE_BUF_SIZE);

	memcpy(staged_send.data, data, n);
	staged_send.len = n;
	return 0;
}

/* --------------------------------------------------------------------------
 * Driver API and DT instantiation
 * -------------------------------------------------------------------------- */

static DEVICE_API(lora, fake_api) = {
	.config     = lora_fake_config,
	.airtime    = lora_fake_airtime,
	.send       = lora_fake_send,
	.send_async = lora_fake_send_async,
	.recv       = lora_fake_recv,
	.recv_async = lora_fake_recv_async,
	.cad        = lora_fake_cad,
	.cad_async  = lora_fake_cad_async,
};

#define LORA_FAKE_DEVICE_INIT(inst)					\
	DEVICE_DT_INST_DEFINE(inst, NULL, NULL, NULL, NULL,		\
			      POST_KERNEL, CONFIG_LORA_INIT_PRIORITY,	\
			      &fake_api);

DT_INST_FOREACH_STATUS_OKAY(LORA_FAKE_DEVICE_INIT)

/* --------------------------------------------------------------------------
 * Test helpers
 * -------------------------------------------------------------------------- */

const struct device *lora_fake_get_device(void)
{
	return DEVICE_DT_INST_GET(0);
}

void lora_fake_reset(void)
{
	RESET_FAKE(lora_fake_config);
	RESET_FAKE(lora_fake_airtime);
	RESET_FAKE(lora_fake_send);
	RESET_FAKE(lora_fake_send_async);
	RESET_FAKE(lora_fake_recv);
	RESET_FAKE(lora_fake_recv_async);
	RESET_FAKE(lora_fake_cad);
	RESET_FAKE(lora_fake_cad_async);

	memset(&staged_recv, 0, sizeof(staged_recv));
	memset(&staged_send, 0, sizeof(staged_send));

	memset(&current_rx, 0, sizeof(current_rx));

	lora_fake_send_fake.custom_fake = send_custom;
	lora_fake_recv_async_fake.custom_fake = recv_async_custom;
}

void lora_fake_set_recv_data(const uint8_t *data, uint8_t len,
			     int16_t rssi, int8_t snr)
{
	uint8_t n = MIN(len, LORA_FAKE_BUF_SIZE);

	memcpy(staged_recv.data, data, n);
	staged_recv.len  = n;
	staged_recv.rssi = rssi;
	staged_recv.snr  = snr;

	lora_fake_recv_fake.custom_fake = recv_custom;
}

void lora_fake_trigger_recv_async(void)
{
	if (!current_rx.cb) {
		return;
	}

	current_rx.cb(DEVICE_DT_INST_GET(0), staged_recv.data, staged_recv.len,
		      staged_recv.rssi, staged_recv.snr, current_rx.user_data);
}

const uint8_t *lora_fake_get_sent_data(uint32_t *len_out)
{
	if (lora_fake_send_fake.call_count == 0) {
		if (len_out) {
			*len_out = 0;
		}
		return NULL;
	}

	if (len_out) {
		*len_out = staged_send.len;
	}
	return staged_send.data;
}
