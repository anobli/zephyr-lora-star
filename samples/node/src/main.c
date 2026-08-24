/*
 * Copyright (c) 2026 Alexandre Bailon <abailon@baylibre.com>
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/drivers/hwinfo.h>
#include <zephyr/logging/log.h>

#include <lora_star/lora_star.h>
#include <lora_star/pairing.h>

LOG_MODULE_REGISTER(node_sample, LOG_LEVEL_INF);

static const struct gpio_dt_spec pairing_btn =
	GPIO_DT_SPEC_GET(DT_ALIAS(sw0), gpios);

static struct gpio_callback       btn_cb;
static struct ls_ctx             *ctx;
static struct ls_node_pairing_ctx pair_ctx;

static void pairing_work_fn(struct k_work *work)
{
	int ret;

	ARG_UNUSED(work);

	LOG_INF("Starting pairing");
	ret = ls_pairing_node_start(ctx, &pair_ctx);
	if (ret < 0) {
		LOG_WRN("Pairing failed: %d", ret);
	} else {
		LOG_INF("Paired — ShortAddr 0x%04x", ctx->own_addr);
	}
}

K_WORK_DEFINE(pairing_work, pairing_work_fn);

static void btn_isr(const struct device *dev, struct gpio_callback *cb,
		    uint32_t pins)
{
	ARG_UNUSED(dev);
	ARG_UNUSED(cb);
	ARG_UNUSED(pins);
	k_work_submit(&pairing_work);
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

	hwinfo_get_device_id(pair_ctx.dev_eui, LS_DEV_EUI_SIZE);

	if (ls_is_paired(ctx)) {
		LOG_INF("Session restored — ShortAddr 0x%04x", ctx->own_addr);
	} else {
		LOG_INF("Not paired — press button to start pairing");
	}

	if (device_is_ready(pairing_btn.port)) {
		gpio_pin_configure_dt(&pairing_btn, GPIO_INPUT);
		gpio_pin_interrupt_configure_dt(&pairing_btn,
						GPIO_INT_EDGE_TO_ACTIVE);
		gpio_init_callback(&btn_cb, btn_isr, BIT(pairing_btn.pin));
		gpio_add_callback(pairing_btn.port, &btn_cb);
	} else {
		LOG_WRN("Pairing button not available");
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
