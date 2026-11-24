/*
 * Copyright (c) 2026 Alexandre Bailon <abailon@baylibre.com>
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ls_fake_radio.h"

#include <string.h>
#include <zephyr/devicetree.h>
#include <zephyr/fff.h>
#include <zephyr/sys/util.h>

DEFINE_FFF_GLOBALS;

#define FAKE_LORA_NODE DT_COMPAT_GET_ANY_STATUS_OKAY(zephyr_fake_lora)

BUILD_ASSERT(DT_NODE_EXISTS(FAKE_LORA_NODE),
	     "ls_fake_radio requires an enabled \"zephyr,fake-lora\" DT node");

#define BUF_SIZE 255

static struct {
	uint8_t data[BUF_SIZE];
	uint8_t len;
	int16_t rssi;
	int8_t snr;
} staged_rx;

static struct {
	uint8_t data[BUF_SIZE];
	uint32_t len;
	bool valid;
} captured_tx;

static struct {
	lora_recv_cb cb;
	void *user_data;
} armed_rx;

static int send_capture(const struct device *dev, uint8_t *data, uint32_t len)
{
	uint32_t n = MIN(len, BUF_SIZE);

	ARG_UNUSED(dev);
	memcpy(captured_tx.data, data, n);
	captured_tx.len = n;
	captured_tx.valid = true;
	return 0;
}

static int recv_async_capture(const struct device *dev, lora_recv_cb cb, void *user_data)
{
	ARG_UNUSED(dev);
	armed_rx.cb = cb;
	armed_rx.user_data = user_data;
	return 0;
}

static int recv_staged(const struct device *dev, uint8_t *data, uint8_t size,
		       k_timeout_t timeout, int16_t *rssi, int8_t *snr)
{
	uint8_t n = MIN(staged_rx.len, size);

	ARG_UNUSED(dev);
	ARG_UNUSED(timeout);
	memcpy(data, staged_rx.data, n);
	if (rssi) {
		*rssi = staged_rx.rssi;
	}
	if (snr) {
		*snr = staged_rx.snr;
	}
	return n;
}

const struct device *ls_fake_radio_dev(void)
{
	return DEVICE_DT_GET(FAKE_LORA_NODE);
}

void ls_fake_radio_reset(void)
{
	memset(&staged_rx, 0, sizeof(staged_rx));
	memset(&captured_tx, 0, sizeof(captured_tx));
	memset(&armed_rx, 0, sizeof(armed_rx));

	fake_lora_send_fake.custom_fake = send_capture;
	fake_lora_recv_async_fake.custom_fake = recv_async_capture;
}

void ls_fake_radio_set_rx(const uint8_t *data, uint8_t len, int16_t rssi, int8_t snr)
{
	uint8_t n = MIN(len, BUF_SIZE);

	memcpy(staged_rx.data, data, n);
	staged_rx.len = n;
	staged_rx.rssi = rssi;
	staged_rx.snr = snr;

	fake_lora_recv_fake.custom_fake = recv_staged;
}

void ls_fake_radio_trigger_rx(void)
{
	if (!armed_rx.cb) {
		return;
	}

	armed_rx.cb(ls_fake_radio_dev(), staged_rx.data, staged_rx.len,
		    staged_rx.rssi, staged_rx.snr, armed_rx.user_data);
}

const uint8_t *ls_fake_radio_get_tx(uint32_t *len_out)
{
	if (len_out) {
		*len_out = captured_tx.valid ? captured_tx.len : 0;
	}
	return captured_tx.valid ? captured_tx.data : NULL;
}
