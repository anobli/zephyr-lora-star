/*
 * Copyright (c) 2026 Alexandre Bailon <abailon@baylibre.com>
 * SPDX-License-Identifier: Apache-2.0
 */

#include <lora_star/mac.h>
#include <lora_star/radio.h>
#include <lora_star/crypto.h>
#include <lora_star/coord.h>

#include "event.h"

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(ls_mac, CONFIG_LORA_STAR_LOG_LEVEL);

int ls_mac_init(struct ls_ctx *ctx)
{
	return ls_radio_init(ctx->radio_dev);
}

/*
 * Resolves the key to use for verifying/decrypting a received DATA/ACK
 * frame claiming to be from src: the node's own session key when src is
 * the coordinator, or that node's session key when this is the coordinator
 * receiving from src. NULL if src has no active session — replay-proofing
 * a stale or forged session comes from there being no valid key to
 * authenticate against, not from a saved counter.
 */
static const uint8_t *ls_resolve_rx_key(struct ls_ctx *ctx, uint16_t src)
{
	if (ctx->own_addr == LS_COORD_ADDR) {
		return ls_coord_get_session_key(src);
	}
	return (src == LS_COORD_ADDR && ctx->_session_active) ? ctx->_session_key : NULL;
}

int ls_mac_send(struct ls_ctx *ctx, struct ls_frame *frame, const uint8_t *key)
{
	uint8_t type;
	int ret;

	if (ctx == NULL || ctx->radio_dev == NULL) {
		return -ENODEV;
	}

	if (frame == NULL) {
		return -EINVAL;
	}

	if (key == NULL) {
		return -EINVAL;
	}

	type = ls_frame_get_type(frame);

	if (type == LS_TYPE_DATA || type == LS_TYPE_ACK ||
	    type == LS_TYPE_JOIN_ACCEPT || type == LS_TYPE_REJOIN_ACCEPT) {
		/*
		 * Pre-increment: FCNT values start at 1, never 0, so the first
		 * frame of a fresh session (session_fcnt_last = 0) is always
		 * accepted by the strict "fcnt > session_fcnt_last" check.
		 */
		ls_frame_set_fcnt(frame, ++ctx->fcnt);
	}

	if (type == LS_TYPE_DATA || type == LS_TYPE_ACK) {
		ret = ls_frame_encrypt(frame, key);
		if (ret) {
			LOG_ERR("Failed to encrypt the frame");
			return ret;
		}
		ret = ls_frame_sign(frame, key);
		if (ret) {
			LOG_ERR("Failed to sign the frame");
			return ret;
		}
	} else {
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
	const uint8_t *key;
	uint16_t frame_src;
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
		frame_src = ls_frame_get_src(&ev.rx);
		key = ls_resolve_rx_key(ctx, frame_src);
		if (!key) {
			LOG_WRN("No active session for 0x%04x, dropping frame", frame_src);
			/*
			 * Only the coordinator replies, and only for a node it
			 * already knows about (ls_coord_notify_allowed() also
			 * rate-limits) — an unrecognised address gets nothing,
			 * so this can't be used to make the coordinator chatter
			 * back to arbitrary spoofed addresses.
			 */
			if (ctx->own_addr == LS_COORD_ADDR && ls_coord_notify_allowed(frame_src)) {
				(void)ls_send_async(ctx, LS_TYPE_SESSION_UNKNOWN,
						    LS_COORD_ADDR, frame_src, 0,
						    NULL, 0, ctx->network_key,
						    false, 0, 0, 0, NULL, NULL);
			}
			return;
		}

		ret = ls_frame_check_signature(&ev.rx, key);
		if (ret) {
			LOG_WRN("MIC check failed, dropping frame");
			return;
		}
		ret = ls_frame_decrypt(&ev.rx, key);
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
