/*
 * Copyright (c) 2026 Alexandre Bailon <abailon@baylibre.com>
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/logging/log.h>

#include <lora_star/lora_star.h>
#include <lora_star/mac.h>
#include <lora_star/coord.h>
#include <lora_star/pairing.h>
#include <lora_star/pairing_button.h>

LOG_MODULE_REGISTER(coord_sample, LOG_LEVEL_INF);

static struct ls_ctx *ctx;

/* --------------------------------------------------------------------------
 * Application callbacks
 * -------------------------------------------------------------------------- */

static void on_join(struct ls_ctx *ls, uint16_t short_addr,
		    const uint8_t dev_eui[LS_DEV_EUI_SIZE], void *user_data)
{
	ARG_UNUSED(ls);
	ARG_UNUSED(user_data);

	LOG_INF("New node: addr=0x%04x EUI=%02x%02x%02x%02x%02x%02x%02x%02x",
		short_addr,
		dev_eui[0], dev_eui[1], dev_eui[2], dev_eui[3],
		dev_eui[4], dev_eui[5], dev_eui[6], dev_eui[7]);
}

static int on_data(struct ls_ctx *ls, struct ls_frame *frame, void *user_data)
{
	uint8_t *payload;
	size_t payload_len;
	uint16_t src;

	ARG_UNUSED(user_data);

	ls_frame_get_payload(frame, &payload, &payload_len);
	src = ls_frame_get_src(frame);

	LOG_INF("Uplink from 0x%04x (%zu bytes): %.*s",
		src, payload_len, (int)payload_len, payload);

	if (ls_frame_get_flags(frame) & LS_FLAG_ACK_REQ) {
		ls_send_ack(ls, src);
	}

	return 0;
}

/* --------------------------------------------------------------------------
 * Main
 * -------------------------------------------------------------------------- */

int main(void)
{
	const struct device *lora_dev = DEVICE_DT_GET(DT_ALIAS(lora0));
	int ret;

	ctx = ls_init(lora_dev);
	if (!ctx) {
		LOG_ERR("ls_init failed");
		return -EIO;
	}

	ret = ls_init_coord(ctx);
	if (ret < 0) {
		LOG_ERR("ls_init_coord failed: %d", ret);
		return ret;
	}

	ls_pairing_button_set_join_cb(on_join, NULL);

	ls_register_data_cb(ctx, LS_BCAST_ADDR, on_data, NULL);

	/* Start listening for uplinks. */
	ls_mac_recv(ctx);

	LOG_INF("Coordinator ready");
	return 0;
}
