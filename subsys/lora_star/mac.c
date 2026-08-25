/*
 * Copyright (c) 2026 Alexandre Bailon <abailon@baylibre.com>
 * SPDX-License-Identifier: Apache-2.0
 */

#include <lora_star/mac.h>
#include <lora_star/radio.h>
#include <lora_star/crypto.h>

#include "event.h"

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(ls_mac, CONFIG_LORA_STAR_LOG_LEVEL);

int ls_mac_init(struct ls_ctx *ctx)
{
	return ls_radio_init(ctx->radio_dev);
}

int ls_mac_send(struct ls_ctx *ctx, struct ls_frame *frame)
{
	uint8_t type;
	int ret;

	if (ctx == NULL || ctx->radio_dev == NULL) {
		return -ENODEV;
	}

	if (frame == NULL) {
		return -EINVAL;
	}

	type = ls_frame_get_type(frame);

	if (type == LS_TYPE_DATA || type == LS_TYPE_ACK) {
		ls_frame_set_src(frame, ctx->own_addr);
		ls_frame_set_fcnt(frame, ctx->fcnt++);
		ret = ls_frame_encrypt(frame, ctx->network_key);
		if (ret) {
			LOG_ERR("Failed to encrypt the frame");
			return ret;
		}
		ret = ls_frame_sign(frame, ctx->network_key);
		if (ret) {
			LOG_ERR("Failed to sign the frame");
			return ret;
		}
	}

	if (ctx->always_on_rx) {
		LOG_DBG("Stopping radio RX operations");
		ls_radio_rx_stop(ctx->radio_dev);
	}

	ret = ls_radio_tx(ctx->radio_dev, frame->buf, LS_FRAME_SIZE(frame->payload_len));

	if (ctx->always_on_rx) {
		LOG_DBG("Resuming radio RX operations");
		ls_mac_recv(ctx);
	}

	return ret;
}

static void mac_recv_cb(const struct device *dev, uint8_t *data, uint16_t size,
			int16_t rssi, int8_t snr, void *user_data)
{
	struct ls_ctx *ctx = user_data;
	struct ls_event ev;
	uint8_t type;
	int ret;

	ARG_UNUSED(dev);
	ARG_UNUSED(snr);

	if (!data || size < LS_OVERHEAD_SIZE) {
		return;
	}

	ret = ls_frame_alloc_buf(&ev.rx, size - LS_OVERHEAD_SIZE);
	if (ret) {
		LOG_WRN("Failed to allocate frame buffer");
		return;
	}

	ev.type   = LS_EVENT_RX;
	ev.rx.rssi = (int8_t)rssi;
	memcpy(ev.rx.buf, data, size);

	type = ls_frame_get_type(&ev.rx);

	if (type == LS_TYPE_DATA || type == LS_TYPE_ACK) {
		ret = ls_frame_check_signature(&ev.rx, ctx->network_key);
		if (ret) {
			LOG_WRN("MIC check failed, dropping frame");
			ls_frame_free_buf(&ev.rx);
			return;
		}
		ret = ls_frame_decrypt(&ev.rx, ctx->network_key);
		if (ret) {
			LOG_WRN("Decryption failed, dropping frame");
			ls_frame_free_buf(&ev.rx);
			return;
		}
	}

	if (k_msgq_put(ctx->_msgq, &ev, K_NO_WAIT) < 0) {
		LOG_WRN("RX queue full, frame dropped");
		ls_frame_free_buf(&ev.rx);
	}
}

int ls_mac_recv(struct ls_ctx *ctx)
{
	if (ctx == NULL || ctx->radio_dev == NULL) {
		return -ENODEV;
	}

	return ls_radio_rx_start(ctx->radio_dev, mac_recv_cb, ctx);
}

int ls_mac_rx_stop(struct ls_ctx *ctx)
{
	if (ctx == NULL || ctx->radio_dev == NULL) {
		return -ENODEV;
	}

	return ls_radio_rx_stop(ctx->radio_dev);
}

uint32_t ls_mac_airtime_ms(struct ls_ctx *ctx, size_t frame_len)
{
	return ls_radio_airtime_ms(ctx->radio_dev, frame_len);
}
