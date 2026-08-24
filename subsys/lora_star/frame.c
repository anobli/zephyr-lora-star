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

int ls_frame_init(struct ls_frame *frame, size_t payload_len, uint8_t *buf, size_t buf_size)
{
	if (buf_size < ls_frame_size(payload_len)) {
		return -ENOMEM;
	}

	frame->buf = buf;
	frame->buf_size = buf_size;
	frame->payload_len = payload_len;

	return 0;
}

int ls_frame_alloc_buf(struct ls_frame *frame, size_t payload_len)
{
	frame->buf = k_malloc(sizeof(*frame) + ls_frame_size(payload_len));
	if (!frame->buf) {
		return -ENOMEM;
	}

	frame->buf_size = ls_frame_size(payload_len);
	frame->payload_len = payload_len;

	return 0;
}

void ls_frame_free_buf(struct ls_frame *frame)
{
	k_free(frame->buf);
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

void ls_frame_set_payload(struct ls_frame *frame, const uint8_t *payload)
{
	struct ls_frame_hdr *hdr = frame_get_hdr(frame);

	memcpy(hdr + 1, payload, frame->payload_len);
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
