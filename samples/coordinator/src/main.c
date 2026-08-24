/*
 * Copyright (c) 2026 Alexandre Bailon <abailon@baylibre.com>
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/logging/log.h>

#include <lora_star/lora_star.h>
#include <lora_star/mac.h>
#include <lora_star/pairing.h>

LOG_MODULE_REGISTER(coord_sample, LOG_LEVEL_INF);

static const struct gpio_dt_spec pairing_btn =
	GPIO_DT_SPEC_GET(DT_ALIAS(sw0), gpios);

static struct gpio_callback        btn_cb;
static struct k_work               btn_work;
static struct ls_ctx              *ctx;
static struct ls_coord_pairing_ctx pair_ctx;

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
 * Button handling
 * -------------------------------------------------------------------------- */

static void btn_work_handler(struct k_work *work)
{
	ARG_UNUSED(work);
	LOG_INF("Pairing button pressed — opening pairing window");
	ls_pairing_coord_start(&pair_ctx);
}

static void btn_isr(const struct device *dev, struct gpio_callback *cb,
		    uint32_t pins)
{
	ARG_UNUSED(dev);
	ARG_UNUSED(pins);
	k_work_submit(&btn_work);
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

	ret = ls_pairing_coord_init(ctx, &pair_ctx, on_join, NULL);
	if (ret < 0) {
		LOG_ERR("ls_pairing_coord_init failed: %d", ret);
		return ret;
	}

	ls_register_data_cb(ctx, LS_BCAST_ADDR, on_data, NULL);

	k_work_init(&btn_work, btn_work_handler);

	if (device_is_ready(pairing_btn.port)) {
		gpio_pin_configure_dt(&pairing_btn, GPIO_INPUT);
		gpio_pin_interrupt_configure_dt(&pairing_btn,
						GPIO_INT_EDGE_TO_ACTIVE);
		gpio_init_callback(&btn_cb, btn_isr, BIT(pairing_btn.pin));
		gpio_add_callback(pairing_btn.port, &btn_cb);
	} else {
		LOG_WRN("Pairing button not available");
	}

	/* Start listening for uplinks. */
	ls_mac_recv(ctx);

	LOG_INF("Coordinator ready");
	return 0;
}
