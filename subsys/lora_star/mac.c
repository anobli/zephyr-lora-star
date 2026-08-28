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

int ls_mac_send(struct ls_ctx *ctx, struct ls_frame *frame, const uint8_t *key)
{
	const uint8_t *use_key;
	uint8_t type;
	int ret;

	if (ctx == NULL || ctx->radio_dev == NULL) {
		return -ENODEV;
	}

	if (frame == NULL) {
		return -EINVAL;
	}

	type = ls_frame_get_type(frame);

	if ((type == LS_TYPE_JOIN_REQ || type == LS_TYPE_JOIN_ACCEPT) && !key) {
		return -EINVAL;
	}

	if (type == LS_TYPE_DATA || type == LS_TYPE_ACK || type == LS_TYPE_JOIN_ACCEPT) {
		/*
		 * Pre-increment: FCNT values start at 1, never 0, so the first
		 * frame from a freshly paired peer (fcnt_last = 0) is always
		 * accepted by the strict "fcnt > fcnt_last" anti-replay check.
		 */
		ls_frame_set_fcnt(frame, ++ctx->fcnt);
	}

	if (type == LS_TYPE_DATA || type == LS_TYPE_ACK) {
		use_key = key ? key : ctx->network_key;
		ret = ls_frame_encrypt(frame, use_key);
		if (ret) {
			LOG_ERR("Failed to encrypt the frame");
			return ret;
		}
		ret = ls_frame_sign(frame, use_key);
		if (ret) {
			LOG_ERR("Failed to sign the frame");
			return ret;
		}
	} else if (key != NULL) {
		ret = ls_frame_sign(frame, key);
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

	if (!data || size < LS_OVERHEAD_SIZE || size > LS_MAX_FRAME_SIZE) {
		return;
	}

	ls_frame_init(&ev.rx);
	ev.type = LS_EVENT_RX;
	ev.rx.rssi = (int8_t)rssi;
	ev.rx.payload_len = size - LS_OVERHEAD_SIZE;
	memcpy(ev.rx.buf, data, size);

	type = ls_frame_get_type(&ev.rx);

	if (type == LS_TYPE_DATA || type == LS_TYPE_ACK) {
		ret = ls_frame_check_signature(&ev.rx, ctx->network_key);
		if (ret) {
			LOG_WRN("MIC check failed, dropping frame");
			return;
		}
		ret = ls_frame_decrypt(&ev.rx, ctx->network_key);
		if (ret) {
			LOG_WRN("Decryption failed, dropping frame");
			return;
		}
	}

	if (k_msgq_put(ctx->_msgq, &ev, K_NO_WAIT) < 0) {
		LOG_WRN("RX queue full, frame dropped");
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
