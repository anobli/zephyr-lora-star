/*
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

ZTEST(lora_star_frame, test_init_no_payload)
{
	uint8_t buf[LS_OVERHEAD_SIZE];
	struct ls_frame frame;
	int ret = ls_frame_init(&frame, 0, buf, sizeof(buf));

	zassert_equal(ret, 0);
	zassert_equal(frame.payload_len, 0);
	zassert_equal(frame.buf, buf);
}

ZTEST(lora_star_frame, test_init_with_payload)
{
	uint8_t buf[LS_OVERHEAD_SIZE + 10];
	struct ls_frame frame;
	int ret = ls_frame_init(&frame, 10, buf, sizeof(buf));

	zassert_equal(ret, 0);
	zassert_equal(frame.payload_len, 10);
}

ZTEST(lora_star_frame, test_init_buffer_too_small)
{
	uint8_t buf[LS_OVERHEAD_SIZE - 1];
	struct ls_frame frame;
	int ret = ls_frame_init(&frame, 0, buf, sizeof(buf));

	zassert_equal(ret, -ENOMEM);
}

ZTEST(lora_star_frame, test_init_join_req_payload_size)
{
	uint8_t buf[LS_FRAME_SIZE(LS_JOIN_REQ_PAYLOAD_SIZE)];
	struct ls_frame frame;
	int ret = ls_frame_init(&frame, LS_JOIN_REQ_PAYLOAD_SIZE, buf, sizeof(buf));

	zassert_equal(ret, 0);
	zassert_equal(frame.payload_len, LS_JOIN_REQ_PAYLOAD_SIZE);
}

ZTEST(lora_star_frame, test_init_max_payload)
{
	uint8_t buf[LS_MAX_FRAME_SIZE];
	struct ls_frame frame;
	int ret = ls_frame_init(&frame, LS_MAX_PAYLOAD_SIZE, buf, sizeof(buf));

	zassert_equal(ret, 0);
	zassert_equal(frame.payload_len, LS_MAX_PAYLOAD_SIZE);
}

/* --------------------------------------------------------------------------
 * Field accessors
 * -------------------------------------------------------------------------- */

ZTEST(lora_star_frame, test_field_type)
{
	uint8_t buf[LS_OVERHEAD_SIZE];
	struct ls_frame frame;

	ls_frame_init(&frame, 0, buf, sizeof(buf));

	ls_frame_set_type(&frame, LS_TYPE_ACK);
	zassert_equal(ls_frame_get_type(&frame), LS_TYPE_ACK);

	ls_frame_set_type(&frame, LS_TYPE_DATA);
	zassert_equal(ls_frame_get_type(&frame), LS_TYPE_DATA);
}

ZTEST(lora_star_frame, test_field_src_dst)
{
	uint8_t buf[LS_OVERHEAD_SIZE];
	struct ls_frame frame;

	ls_frame_init(&frame, 0, buf, sizeof(buf));
	ls_frame_set_src(&frame, 0x0001);
	ls_frame_set_dst(&frame, LS_COORD_ADDR);

	zassert_equal(ls_frame_get_src(&frame), 0x0001);
	zassert_equal(ls_frame_get_dst(&frame), LS_COORD_ADDR);
}

ZTEST(lora_star_frame, test_field_fcnt)
{
	uint8_t buf[LS_OVERHEAD_SIZE];
	struct ls_frame frame;

	ls_frame_init(&frame, 0, buf, sizeof(buf));
	ls_frame_set_fcnt(&frame, 0xDEADBEEF);

	zassert_equal(ls_frame_get_fcnt(&frame), 0xDEADBEEF);
}

ZTEST(lora_star_frame, test_field_flags)
{
	uint8_t buf[LS_OVERHEAD_SIZE];
	struct ls_frame frame;

	ls_frame_init(&frame, 0, buf, sizeof(buf));
	ls_frame_set_flags(&frame, LS_FLAG_ACK_REQ | LS_FLAG_ACK_PENDING);

	zassert_equal(ls_frame_get_flags(&frame), LS_FLAG_ACK_REQ | LS_FLAG_ACK_PENDING);
}

ZTEST(lora_star_frame, test_field_payload)
{
	uint8_t buf[LS_OVERHEAD_SIZE + 8];
	uint8_t data_in[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
	uint8_t *data_out;
	size_t len;
	struct ls_frame frame;

	ls_frame_init(&frame, 8, buf, sizeof(buf));
	ls_frame_set_payload(&frame, data_in);
	ls_frame_get_payload(&frame, &data_out, &len);

	zassert_equal(len, 8);
	zassert_mem_equal(data_out, data_in, 8);
	/* Zero-copy: pointer must be inside buf */
	zassert_true(data_out >= buf && data_out < buf + sizeof(buf));
}

ZTEST(lora_star_frame, test_field_mic)
{
	uint8_t buf[LS_OVERHEAD_SIZE];
	uint8_t mic_in[LS_MIC_SIZE] = {0x11, 0x22, 0x33, 0x44};
	uint8_t mic_out[LS_MIC_SIZE];
	struct ls_frame frame;

	ls_frame_init(&frame, 0, buf, sizeof(buf));
	ls_frame_set_mic(&frame, mic_in);
	ls_frame_get_mic(&frame, mic_out);

	zassert_mem_equal(mic_out, mic_in, LS_MIC_SIZE);
}

ZTEST(lora_star_frame, test_content_size)
{
	uint8_t buf[LS_OVERHEAD_SIZE + 10];
	struct ls_frame frame;

	ls_frame_init(&frame, 10, buf, sizeof(buf));

	zassert_equal(ls_frame_content_size(&frame), LS_HDR_SIZE + 10);
}

/* --------------------------------------------------------------------------
 * Wire layout (little-endian encoding)
 * -------------------------------------------------------------------------- */

ZTEST(lora_star_frame, test_little_endian_layout)
{
	uint8_t buf[LS_OVERHEAD_SIZE];
	struct ls_frame frame;

	ls_frame_init(&frame, 0, buf, sizeof(buf));
	ls_frame_set_type(&frame, LS_TYPE_ACK);
	ls_frame_set_src(&frame, 0x1234);
	ls_frame_set_dst(&frame, 0x5678);
	ls_frame_set_fcnt(&frame, 0xABCD);
	ls_frame_set_flags(&frame, 0x03);

	/* TYPE(1) | SRC(2) | DST(2) | FCNT(4) | FLAGS(1) */
	zassert_equal(buf[0], LS_TYPE_ACK);
	/* SRC at buf[1..2], little-endian */
	zassert_equal(buf[1], 0x34);
	zassert_equal(buf[2], 0x12);
	/* DST at buf[3..4], little-endian */
	zassert_equal(buf[3], 0x78);
	zassert_equal(buf[4], 0x56);
	/* FCNT at buf[5..8], little-endian */
	zassert_equal(buf[5], 0xCD);
	zassert_equal(buf[6], 0xAB);
	zassert_equal(buf[7], 0x00);
	zassert_equal(buf[8], 0x00);
	/* FLAGS at buf[9] */
	zassert_equal(buf[9], 0x03);
}

/* --------------------------------------------------------------------------
 * Round-trip: set all fields, re-wrap same buffer, read all fields back
 * -------------------------------------------------------------------------- */

ZTEST(lora_star_frame, test_round_trip)
{
	uint8_t buf[LS_OVERHEAD_SIZE + 8];
	uint8_t payload_in[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
	uint8_t mic_in[LS_MIC_SIZE] = {0xAA, 0xBB, 0xCC, 0xDD};
	uint8_t mic_out[LS_MIC_SIZE];
	uint8_t *payload_out;
	size_t payload_len;
	struct ls_frame tx, rx;

	ls_frame_init(&tx, 8, buf, sizeof(buf));
	ls_frame_set_type(&tx, LS_TYPE_DATA);
	ls_frame_set_src(&tx, 0x0003);
	ls_frame_set_dst(&tx, LS_COORD_ADDR);
	ls_frame_set_fcnt(&tx, 99);
	ls_frame_set_flags(&tx, LS_FLAG_ACK_REQ);
	ls_frame_set_payload(&tx, payload_in);
	ls_frame_set_mic(&tx, mic_in);

	/* Simulate receive: wrap same raw buffer */
	ls_frame_init(&rx, 8, buf, sizeof(buf));

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
