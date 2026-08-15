#ifndef LORA_STAR_LS_FRAME_H
#define LORA_STAR_LS_FRAME_H

#include <stdint.h>
#include <stddef.h>
#include <zephyr/sys/util.h>

/* Addressing */
#define LS_BCAST_ADDR   0xFFFFU
#define LS_COORD_ADDR   0x0000U
#define LS_ADDR_MIN     0x0001U
#define LS_ADDR_MAX     0xFFFEU

/* Frame types */
#define LS_TYPE_JOIN_REQ    0x01U
#define LS_TYPE_JOIN_ACCEPT 0x02U
#define LS_TYPE_DATA        0x03U
#define LS_TYPE_ACK         0x04U

/* FLAGS bits */
#define LS_FLAG_ACK_REQ     BIT(0)
#define LS_FLAG_ACK_PENDING BIT(1)

/* Sizes: TYPE(1)+SRC(2)+DST(2)+FCNT(4)+FLAGS(1) = 10, MIC(4) = 14 overhead */
#define LS_HEADER_SIZE      10U
#define LS_MIC_SIZE         4U
#define LS_OVERHEAD_SIZE    (LS_HEADER_SIZE + LS_MIC_SIZE)
#define LS_MAX_FRAME_SIZE   128U
#define LS_MAX_PAYLOAD_SIZE (LS_MAX_FRAME_SIZE - LS_OVERHEAD_SIZE)  /* 114 */

/* Field sizes */
#define LS_DEV_EUI_SIZE     8U
#define LS_PUBKEY_SIZE      32U
#define LS_NONCE_SIZE       4U
#define LS_SESSION_KEY_SIZE 16U

/* JOIN_REQ payload: DevEUI(8) + NodePubKey(32) + Nonce(4) = 44 bytes */
#define LS_JOIN_REQ_PAYLOAD_SIZE   (LS_DEV_EUI_SIZE + LS_PUBKEY_SIZE + LS_NONCE_SIZE)

/* JOIN_ACCEPT payload: CoordPubKey(32) + EncShortAddr(2) = 34 bytes */
#define LS_JOIN_ACCEPT_PAYLOAD_SIZE (LS_PUBKEY_SIZE + sizeof(uint16_t))

struct ls_frame_hdr {
	uint8_t  type;
	uint16_t src;
	uint16_t dst;
	uint32_t fcnt;
	uint8_t  flags;
} __packed;

struct ls_join_req_payload {
	uint8_t dev_eui[LS_DEV_EUI_SIZE];
	uint8_t node_pub_key[LS_PUBKEY_SIZE];
	uint8_t nonce[LS_NONCE_SIZE];
} __packed;

struct ls_join_accept_payload {
	uint8_t  coord_pub_key[LS_PUBKEY_SIZE];
	uint16_t enc_short_addr;
} __packed;

/* Per-node record persisted by the coordinator in ZMS */
struct ls_node_record {
	uint8_t  dev_eui[LS_DEV_EUI_SIZE];
	uint8_t  session_key[LS_SESSION_KEY_SIZE];
	uint32_t fcnt_last;
} __packed;

/*
 * Encode a frame into buf[].
 *
 * header and payload are written, then the caller must append MIC (4 bytes)
 * separately after computing it over the written bytes.  Returns the number
 * of bytes written before the MIC (header + payload), or negative errno.
 */
int ls_frame_encode(uint8_t *buf, size_t buf_size,
		    const struct ls_frame_hdr *hdr,
		    const uint8_t *payload, uint8_t payload_len);

/*
 * Decode a raw frame buffer.
 *
 * On success *payload points into buf (zero-copy), payload_len is set, and
 * *mic points to the 4-byte MIC at the tail.  Returns 0 or negative errno.
 */
int ls_frame_decode(const uint8_t *buf, size_t buf_len,
		    struct ls_frame_hdr *hdr,
		    const uint8_t **payload, uint8_t *payload_len,
		    const uint8_t **mic);

#endif /* LORA_STAR_LS_FRAME_H */
