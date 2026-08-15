/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/ztest.h>
#include <zephyr/sys/byteorder.h>
#include <string.h>
#include <errno.h>
#include <lora_star/ls_frame.h>

/* --------------------------------------------------------------------------
 * Helpers
 * -------------------------------------------------------------------------- */

static struct ls_frame_hdr make_hdr(uint8_t type, uint16_t src, uint16_t dst,
				    uint16_t fcnt, uint8_t flags)
{
	return (struct ls_frame_hdr){
		.type  = type,
		.src   = src,
		.dst   = dst,
		.fcnt  = fcnt,
		.flags = flags,
	};
}

/* --------------------------------------------------------------------------
 * Encode tests
 * -------------------------------------------------------------------------- */

ZTEST(lora_star_frame, test_encode_no_payload)
{
	uint8_t buf[LS_OVERHEAD_SIZE];
	struct ls_frame_hdr hdr = make_hdr(LS_TYPE_ACK, 0x0001, 0x0000, 42, 0);
	int ret = ls_frame_encode(buf, sizeof(buf), &hdr, NULL, 0);

	zassert_equal(ret, LS_HEADER_SIZE, "expected %d, got %d", LS_HEADER_SIZE, ret);
	zassert_equal(buf[0], LS_TYPE_ACK);
}

ZTEST(lora_star_frame, test_encode_with_payload)
{
	uint8_t buf[LS_OVERHEAD_SIZE + 10];
	uint8_t payload[10];
	struct ls_frame_hdr hdr = make_hdr(LS_TYPE_DATA, 0x0002, 0x0000, 7, LS_FLAG_ACK_REQ);

	memset(payload, 0xAB, sizeof(payload));
	int ret = ls_frame_encode(buf, sizeof(buf), &hdr, payload, sizeof(payload));

	zassert_equal(ret, LS_HEADER_SIZE + 10);
	zassert_mem_equal(&buf[LS_HEADER_SIZE], payload, sizeof(payload));
}

ZTEST(lora_star_frame, test_encode_buffer_too_small)
{
	uint8_t buf[LS_OVERHEAD_SIZE - 1];
	struct ls_frame_hdr hdr = make_hdr(LS_TYPE_ACK, 0x0001, 0x0000, 0, 0);
	int ret = ls_frame_encode(buf, sizeof(buf), &hdr, NULL, 0);

	zassert_equal(ret, -ENOMEM);
}

ZTEST(lora_star_frame, test_encode_little_endian)
{
	uint8_t buf[LS_OVERHEAD_SIZE];
	struct ls_frame_hdr hdr = make_hdr(LS_TYPE_ACK, 0x1234, 0x5678, 0xABCD, 0x03);

	ls_frame_encode(buf, sizeof(buf), &hdr, NULL, 0);

	/* SRC at buf[1..2], DST at buf[3..4], FCNT at buf[5..8], FLAGS at buf[9] — all little-endian */
	zassert_equal(buf[1], 0x34);
	zassert_equal(buf[2], 0x12);
	zassert_equal(buf[3], 0x78);
	zassert_equal(buf[4], 0x56);
	zassert_equal(buf[5], 0xCD);
	zassert_equal(buf[6], 0xAB);
	zassert_equal(buf[7], 0x00);
	zassert_equal(buf[8], 0x00);
	zassert_equal(buf[9], 0x03);
}

ZTEST(lora_star_frame, test_encode_mic_slot_zeroed)
{
	uint8_t payload[4] = {1, 2, 3, 4};
	uint8_t buf[LS_OVERHEAD_SIZE + sizeof(payload)];
	struct ls_frame_hdr hdr = make_hdr(LS_TYPE_DATA, 1, 0, 0, 0);

	memset(buf, 0xFF, sizeof(buf));
	int written = ls_frame_encode(buf, sizeof(buf), &hdr, payload, sizeof(payload));

	const uint8_t *mic_slot = &buf[written];

	zassert_equal(mic_slot[0], 0);
	zassert_equal(mic_slot[1], 0);
	zassert_equal(mic_slot[2], 0);
	zassert_equal(mic_slot[3], 0);
}

ZTEST(lora_star_frame, test_encode_join_req_payload_size)
{
	uint8_t payload[LS_JOIN_REQ_PAYLOAD_SIZE];
	uint8_t buf[LS_OVERHEAD_SIZE + LS_JOIN_REQ_PAYLOAD_SIZE];
	struct ls_frame_hdr hdr = make_hdr(LS_TYPE_JOIN_REQ, LS_BCAST_ADDR, LS_COORD_ADDR, 0, 0);

	memset(payload, 0x55, sizeof(payload));
	int ret = ls_frame_encode(buf, sizeof(buf), &hdr, payload, sizeof(payload));

	zassert_equal(ret, LS_HEADER_SIZE + LS_JOIN_REQ_PAYLOAD_SIZE);
}

ZTEST(lora_star_frame, test_encode_max_payload)
{
	uint8_t payload[LS_MAX_PAYLOAD_SIZE];
	uint8_t buf[LS_MAX_FRAME_SIZE];
	struct ls_frame_hdr hdr = make_hdr(LS_TYPE_DATA, 1, 0, 0, 0);

	memset(payload, 0x77, sizeof(payload));
	int ret = ls_frame_encode(buf, sizeof(buf), &hdr, payload, sizeof(payload));

	zassert_equal(ret, LS_HEADER_SIZE + LS_MAX_PAYLOAD_SIZE);
}

/* --------------------------------------------------------------------------
 * Decode tests
 * -------------------------------------------------------------------------- */

ZTEST(lora_star_frame, test_decode_round_trip)
{
	uint8_t payload_in[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
	uint8_t buf[LS_OVERHEAD_SIZE + sizeof(payload_in)];
	struct ls_frame_hdr hdr_in = make_hdr(LS_TYPE_DATA, 0x0003, 0x0000, 99, LS_FLAG_ACK_REQ);

	ls_frame_encode(buf, sizeof(buf), &hdr_in, payload_in, sizeof(payload_in));

	struct ls_frame_hdr hdr_out;
	const uint8_t *payload_out, *mic;
	uint8_t payload_len;

	int ret = ls_frame_decode(buf, sizeof(buf), &hdr_out, &payload_out, &payload_len, &mic);

	zassert_equal(ret, 0);
	zassert_equal(hdr_out.type,  hdr_in.type);
	zassert_equal(hdr_out.src,   hdr_in.src);
	zassert_equal(hdr_out.dst,   hdr_in.dst);
	zassert_equal(hdr_out.fcnt,  hdr_in.fcnt);
	zassert_equal(hdr_out.flags, hdr_in.flags);
	zassert_equal(payload_len, sizeof(payload_in));
	zassert_mem_equal(payload_out, payload_in, sizeof(payload_in));
}

ZTEST(lora_star_frame, test_decode_too_short)
{
	uint8_t buf[LS_OVERHEAD_SIZE - 1] = {0};
	struct ls_frame_hdr hdr;
	const uint8_t *payload, *mic;
	uint8_t payload_len;

	int ret = ls_frame_decode(buf, sizeof(buf), &hdr, &payload, &payload_len, &mic);

	zassert_equal(ret, -EINVAL);
}

ZTEST(lora_star_frame, test_decode_no_payload)
{
	uint8_t buf[LS_OVERHEAD_SIZE];
	struct ls_frame_hdr hdr_in = make_hdr(LS_TYPE_ACK, 0, 1, 5, 0);

	ls_frame_encode(buf, sizeof(buf), &hdr_in, NULL, 0);

	struct ls_frame_hdr hdr_out;
	const uint8_t *payload, *mic;
	uint8_t payload_len;

	int ret = ls_frame_decode(buf, sizeof(buf), &hdr_out, &payload, &payload_len, &mic);

	zassert_equal(ret, 0);
	zassert_equal(payload_len, 0);
	zassert_is_null(payload);
	zassert_not_null(mic);
}

ZTEST(lora_star_frame, test_decode_mic_pointer)
{
	uint8_t payload_data[4] = {0xDE, 0xAD, 0xBE, 0xEF};
	uint8_t buf[LS_OVERHEAD_SIZE + sizeof(payload_data)];
	struct ls_frame_hdr hdr = make_hdr(LS_TYPE_DATA, 1, 0, 0, 0);

	ls_frame_encode(buf, sizeof(buf), &hdr, payload_data, sizeof(payload_data));

	/* Write a known MIC pattern into the MIC slot */
	uint8_t *mic_slot = &buf[LS_HEADER_SIZE + sizeof(payload_data)];
	mic_slot[0] = 0x11;
	mic_slot[1] = 0x22;
	mic_slot[2] = 0x33;
	mic_slot[3] = 0x44;

	struct ls_frame_hdr hdr_out;
	const uint8_t *payload, *mic;
	uint8_t payload_len;

	ls_frame_decode(buf, sizeof(buf), &hdr_out, &payload, &payload_len, &mic);

	zassert_equal(mic[0], 0x11);
	zassert_equal(mic[1], 0x22);
	zassert_equal(mic[2], 0x33);
	zassert_equal(mic[3], 0x44);
	/* Zero-copy: payload pointer must be inside buf */
	zassert_true(payload >= buf && payload < buf + sizeof(buf));
}

ZTEST(lora_star_frame, test_decode_exactly_overhead)
{
	uint8_t buf[LS_OVERHEAD_SIZE];
	struct ls_frame_hdr hdr;
	const uint8_t *payload, *mic;
	uint8_t payload_len;

	memset(buf, 0, sizeof(buf));
	int ret = ls_frame_decode(buf, LS_OVERHEAD_SIZE, &hdr, &payload, &payload_len, &mic);

	zassert_equal(ret, 0);
	zassert_equal(payload_len, 0);
}

ZTEST_SUITE(lora_star_frame, NULL, NULL, NULL, NULL, NULL);
