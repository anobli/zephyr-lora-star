/*
 * Copyright (c) 2026 Alexandre Bailon <abailon@baylibre.com>
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/byteorder.h>

#include <lora_star/frame.h>

size_t ls_frame_size(size_t payload_len)
{
	return LS_FRAME_SIZE(payload_len);
}

void ls_frame_init(struct ls_frame *frame)
{
	frame->payload_len = 0;
}

void ls_frame_build(struct ls_frame *frame,
		    uint8_t type, uint16_t src, uint16_t dst, uint8_t flags)
{
	ls_frame_init(frame);
	ls_frame_set_type(frame, type);
	ls_frame_set_src(frame, src);
	ls_frame_set_dst(frame, dst);
	ls_frame_set_flags(frame, flags);
}

static struct ls_frame_hdr *frame_get_hdr(struct ls_frame *frame)
{
	return (struct ls_frame_hdr *)frame->buf;
}

void ls_frame_set_type(struct ls_frame *frame, uint8_t type)
{
	struct ls_frame_hdr *hdr = frame_get_hdr(frame);

	hdr->type = type;
}

uint8_t ls_frame_get_type(struct ls_frame *frame)
{
	struct ls_frame_hdr *hdr = frame_get_hdr(frame);

	return hdr->type;
}

void ls_frame_set_src(struct ls_frame *frame, uint16_t src)
{
	struct ls_frame_hdr *hdr = frame_get_hdr(frame);

	sys_put_le16(src, (uint8_t *)&hdr->src);
}

uint16_t ls_frame_get_src(struct ls_frame *frame)
{
	struct ls_frame_hdr *hdr = frame_get_hdr(frame);

	return sys_get_le16((uint8_t *)&hdr->src);
}

void ls_frame_set_dst(struct ls_frame *frame, uint16_t dst)
{
	struct ls_frame_hdr *hdr = frame_get_hdr(frame);

	sys_put_le16(dst, (uint8_t *)&hdr->dst);
}

uint16_t ls_frame_get_dst(struct ls_frame *frame)
{
	struct ls_frame_hdr *hdr = frame_get_hdr(frame);

	return sys_get_le16((uint8_t *)&hdr->dst);
}

void ls_frame_set_fcnt(struct ls_frame *frame, uint32_t fcnt)
{
	struct ls_frame_hdr *hdr = frame_get_hdr(frame);

	sys_put_le32(fcnt, (uint8_t *)&hdr->fcnt);
}

uint32_t ls_frame_get_fcnt(struct ls_frame *frame)
{
	struct ls_frame_hdr *hdr = frame_get_hdr(frame);

	return sys_get_le32((uint8_t *)&hdr->fcnt);
}

void ls_frame_set_flags(struct ls_frame *frame, uint8_t flags)
{
	struct ls_frame_hdr *hdr = frame_get_hdr(frame);

	hdr->flags = flags;
}

uint8_t ls_frame_get_flags(struct ls_frame *frame)
{
	struct ls_frame_hdr *hdr = frame_get_hdr(frame);

	return hdr->flags;
}

int ls_frame_set_payload(struct ls_frame *frame, const uint8_t *payload, size_t len)
{
	struct ls_frame_hdr *hdr = frame_get_hdr(frame);

	if (len > LS_MAX_PAYLOAD_SIZE) {
		return -EINVAL;
	}

	frame->payload_len = len;
	memcpy(hdr + 1, payload, len);
	return 0;
}

void ls_frame_get_payload(struct ls_frame *frame, uint8_t **payload, size_t *payload_len)
{
	struct ls_frame_hdr *hdr = frame_get_hdr(frame);

	*payload = (uint8_t *)(hdr + 1);
	*payload_len = frame->payload_len;
}

void ls_frame_set_mic(struct ls_frame *frame, const uint8_t mic[LS_MIC_SIZE])
{
	uint8_t *payload;
	size_t payload_len;

	ls_frame_get_payload(frame, &payload, &payload_len);
	memcpy(payload + payload_len, mic, LS_MIC_SIZE);
}

void ls_frame_get_mic(struct ls_frame *frame, uint8_t mic[LS_MIC_SIZE])
{
	uint8_t *payload;
	size_t payload_len;

	ls_frame_get_payload(frame, &payload, &payload_len);
	memcpy(mic, payload + payload_len, LS_MIC_SIZE);
}

size_t ls_frame_content_size(struct ls_frame *frame)
{
	return frame->payload_len + sizeof(struct ls_frame_hdr);
}
