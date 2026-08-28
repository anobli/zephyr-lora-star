/*
 * Copyright (c) 2026 Alexandre Bailon <abailon@baylibre.com>
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/ztest.h>
#include <zephyr/sys/byteorder.h>
#include <string.h>
#include <errno.h>
#include <lora_star/frame.h>
#include <lora_star/pairing.h>

/* --------------------------------------------------------------------------
 * Frame size helpers
 * -------------------------------------------------------------------------- */

ZTEST(lora_star_frame, test_frame_size)
{
	zassert_equal(ls_frame_size(0), LS_OVERHEAD_SIZE);
	zassert_equal(ls_frame_size(10), LS_OVERHEAD_SIZE + 10);
	zassert_equal(ls_frame_size(LS_MAX_PAYLOAD_SIZE), LS_MAX_FRAME_SIZE);
}

/* --------------------------------------------------------------------------
 * Initialisation
 * -------------------------------------------------------------------------- */

ZTEST(lora_star_frame, test_init_zeros_payload_len)
{
	struct ls_frame frame;

	ls_frame_init(&frame);

	zassert_equal(frame.payload_len, 0);
}

/* --------------------------------------------------------------------------
 * ls_frame_set_payload — size validation and data copying
 * -------------------------------------------------------------------------- */

ZTEST(lora_star_frame, test_set_payload_one_byte)
{
	struct ls_frame frame;
	uint8_t data[1] = {0xAB};
	uint8_t *out;
	size_t len;
	int ret;

	ls_frame_init(&frame);
	ret = ls_frame_set_payload(&frame, data, 1);

	zassert_equal(ret, 0);
	zassert_equal(frame.payload_len, 1);
	ls_frame_get_payload(&frame, &out, &len);
	zassert_equal(out[0], 0xAB);
}

ZTEST(lora_star_frame, test_set_payload_mid_size)
{
	struct ls_frame frame;
	uint8_t data[32] = {0};
	int ret;

	data[0] = 0x11;
	data[31] = 0xFF;

	ls_frame_init(&frame);
	ret = ls_frame_set_payload(&frame, data, sizeof(data));

	zassert_equal(ret, 0);
	zassert_equal(frame.payload_len, 32);
}

ZTEST(lora_star_frame, test_set_payload_join_req_size)
{
	struct ls_frame frame;
	uint8_t data[LS_JOIN_REQ_PAYLOAD_SIZE] = {0};
	int ret;

	ls_frame_init(&frame);
	ret = ls_frame_set_payload(&frame, data, LS_JOIN_REQ_PAYLOAD_SIZE);

	zassert_equal(ret, 0);
	zassert_equal(frame.payload_len, LS_JOIN_REQ_PAYLOAD_SIZE);
}

ZTEST(lora_star_frame, test_set_payload_max_size)
{
	struct ls_frame frame;
	uint8_t data[LS_MAX_PAYLOAD_SIZE] = {0};
	int ret;

	ls_frame_init(&frame);
	ret = ls_frame_set_payload(&frame, data, LS_MAX_PAYLOAD_SIZE);

	zassert_equal(ret, 0);
	zassert_equal(frame.payload_len, LS_MAX_PAYLOAD_SIZE);
}

ZTEST(lora_star_frame, test_set_payload_overflow)
{
	struct ls_frame frame;
	uint8_t data[LS_MAX_PAYLOAD_SIZE + 1] = {0};
	int ret;

	ls_frame_init(&frame);
	ret = ls_frame_set_payload(&frame, data, LS_MAX_PAYLOAD_SIZE + 1);

	zassert_equal(ret, -EINVAL);
	/* frame must be unmodified */
	zassert_equal(frame.payload_len, 0);
}

ZTEST(lora_star_frame, test_set_payload_copies_data)
{
	uint8_t data_in[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
	uint8_t *data_out;
	size_t len;
	struct ls_frame frame;
	int ret;

	ls_frame_init(&frame);
	ret = ls_frame_set_payload(&frame, data_in, 8);

	zassert_equal(ret, 0);
	ls_frame_get_payload(&frame, &data_out, &len);
	zassert_equal(len, 8);
	zassert_mem_equal(data_out, data_in, 8);
	/* Zero-copy: pointer must be inside frame.buf */
	zassert_true(data_out >= frame.buf && data_out < frame.buf + sizeof(frame.buf));
}

/* --------------------------------------------------------------------------
 * Field accessors
 * -------------------------------------------------------------------------- */

ZTEST(lora_star_frame, test_field_type)
{
	struct ls_frame frame;

	ls_frame_init(&frame);

	ls_frame_set_type(&frame, LS_TYPE_ACK);
	zassert_equal(ls_frame_get_type(&frame), LS_TYPE_ACK);

	ls_frame_set_type(&frame, LS_TYPE_DATA);
	zassert_equal(ls_frame_get_type(&frame), LS_TYPE_DATA);
}

ZTEST(lora_star_frame, test_field_src_dst)
{
	struct ls_frame frame;

	ls_frame_init(&frame);
	ls_frame_set_src(&frame, 0x0001);
	ls_frame_set_dst(&frame, LS_COORD_ADDR);

	zassert_equal(ls_frame_get_src(&frame), 0x0001);
	zassert_equal(ls_frame_get_dst(&frame), LS_COORD_ADDR);
}

ZTEST(lora_star_frame, test_field_fcnt)
{
	struct ls_frame frame;

	ls_frame_init(&frame);
	ls_frame_set_fcnt(&frame, 0xDEADBEEF);

	zassert_equal(ls_frame_get_fcnt(&frame), 0xDEADBEEF);
}

ZTEST(lora_star_frame, test_field_flags)
{
	struct ls_frame frame;

	ls_frame_init(&frame);
	ls_frame_set_flags(&frame, LS_FLAG_ACK_REQ | LS_FLAG_ACK_PENDING);

	zassert_equal(ls_frame_get_flags(&frame), LS_FLAG_ACK_REQ | LS_FLAG_ACK_PENDING);
}

ZTEST(lora_star_frame, test_field_mic)
{
	uint8_t mic_in[LS_MIC_SIZE] = {0x11, 0x22, 0x33, 0x44};
	uint8_t mic_out[LS_MIC_SIZE];
	struct ls_frame frame;

	ls_frame_init(&frame);
	ls_frame_set_mic(&frame, mic_in);
	ls_frame_get_mic(&frame, mic_out);

	zassert_mem_equal(mic_out, mic_in, LS_MIC_SIZE);
}

ZTEST(lora_star_frame, test_content_size)
{
	struct ls_frame frame;
	uint8_t dummy[10] = {0};

	ls_frame_init(&frame);
	ls_frame_set_payload(&frame, dummy, 10);

	zassert_equal(ls_frame_content_size(&frame), LS_HDR_SIZE + 10);
}

/* --------------------------------------------------------------------------
 * Wire layout (little-endian encoding)
 * -------------------------------------------------------------------------- */

ZTEST(lora_star_frame, test_little_endian_layout)
{
	struct ls_frame frame;

	ls_frame_init(&frame);
	ls_frame_set_type(&frame, LS_TYPE_ACK);
	ls_frame_set_src(&frame, 0x1234);
	ls_frame_set_dst(&frame, 0x5678);
	ls_frame_set_fcnt(&frame, 0xABCD);
	ls_frame_set_flags(&frame, 0x03);

	/* TYPE(1) | SRC(2) | DST(2) | FCNT(4) | FLAGS(1) */
	zassert_equal(frame.buf[0], LS_TYPE_ACK);
	/* SRC at buf[1..2], little-endian */
	zassert_equal(frame.buf[1], 0x34);
	zassert_equal(frame.buf[2], 0x12);
	/* DST at buf[3..4], little-endian */
	zassert_equal(frame.buf[3], 0x78);
	zassert_equal(frame.buf[4], 0x56);
	/* FCNT at buf[5..8], little-endian */
	zassert_equal(frame.buf[5], 0xCD);
	zassert_equal(frame.buf[6], 0xAB);
	zassert_equal(frame.buf[7], 0x00);
	zassert_equal(frame.buf[8], 0x00);
	/* FLAGS at buf[9] */
	zassert_equal(frame.buf[9], 0x03);
}

/* --------------------------------------------------------------------------
 * Round-trip: set all fields, copy wire bytes, read all fields back
 * -------------------------------------------------------------------------- */

ZTEST(lora_star_frame, test_round_trip)
{
	uint8_t payload_in[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
	uint8_t mic_in[LS_MIC_SIZE] = {0xAA, 0xBB, 0xCC, 0xDD};
	uint8_t mic_out[LS_MIC_SIZE];
	uint8_t *payload_out;
	size_t payload_len;
	struct ls_frame tx, rx;

	ls_frame_init(&tx);
	ls_frame_set_type(&tx, LS_TYPE_DATA);
	ls_frame_set_src(&tx, 0x0003);
	ls_frame_set_dst(&tx, LS_COORD_ADDR);
	ls_frame_set_fcnt(&tx, 99);
	ls_frame_set_flags(&tx, LS_FLAG_ACK_REQ);
	ls_frame_set_payload(&tx, payload_in, 8);
	ls_frame_set_mic(&tx, mic_in);

	/* Simulate receive: copy wire bytes into a fresh frame */
	ls_frame_init(&rx);
	rx.payload_len = 8;
	memcpy(rx.buf, tx.buf, LS_FRAME_SIZE(8));

	zassert_equal(ls_frame_get_type(&rx),  LS_TYPE_DATA);
	zassert_equal(ls_frame_get_src(&rx),   0x0003);
	zassert_equal(ls_frame_get_dst(&rx),   LS_COORD_ADDR);
	zassert_equal(ls_frame_get_fcnt(&rx),  99);
	zassert_equal(ls_frame_get_flags(&rx), LS_FLAG_ACK_REQ);

	ls_frame_get_payload(&rx, &payload_out, &payload_len);
	zassert_equal(payload_len, 8);
	zassert_mem_equal(payload_out, payload_in, 8);

	ls_frame_get_mic(&rx, mic_out);
	zassert_mem_equal(mic_out, mic_in, LS_MIC_SIZE);
}

ZTEST_SUITE(lora_star_frame, NULL, NULL, NULL, NULL, NULL);
