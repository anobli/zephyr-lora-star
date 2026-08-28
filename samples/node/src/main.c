/*
 * Copyright (c) 2026 Alexandre Bailon <abailon@baylibre.com>
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/logging/log.h>

#include <lora_star/lora_star.h>
#include <lora_star/pairing.h>
#include <lora_star/pairing_button.h>

LOG_MODULE_REGISTER(node_sample, LOG_LEVEL_INF);

static struct ls_ctx *ctx;

static void on_pairing_done(struct ls_ctx *ls, int result, void *user_data)
{
	ARG_UNUSED(user_data);

	if (result < 0) {
		LOG_WRN("Pairing failed: %d", result);
	} else {
		LOG_INF("Paired — ShortAddr 0x%04x", ls->own_addr);
	}
}

int main(void)
{
	const struct device *lora_dev = DEVICE_DT_GET(DT_ALIAS(lora0));
	uint32_t counter = 0;
	char msg[32];
	int n, ret;

	ctx = ls_init(lora_dev);
	if (!ctx) {
		LOG_ERR("ls_init failed");
		return -EIO;
	}

	ls_pairing_button_set_done_cb(on_pairing_done, NULL);

	if (ls_is_paired(ctx)) {
		LOG_INF("Session restored — ShortAddr 0x%04x", ctx->own_addr);
	} else {
		LOG_INF("Not paired — press button to start pairing");
	}

	LOG_INF("Node ready");

	while (true) {
		k_sleep(K_SECONDS(30));

		if (!ls_is_paired(ctx)) {
			LOG_WRN("Not paired, skipping uplink");
			continue;
		}

		n = snprintf(msg, sizeof(msg), "ping %u", counter++);
		ret = ls_send_data_ack(ctx, LS_COORD_ADDR, (const uint8_t *)msg, n);
		if (ret < 0) {
			LOG_WRN("Send failed: %d", ret);
		} else {
			LOG_INF("Sent and ACKed: %s", msg);
		}
	}

	return 0;
}
