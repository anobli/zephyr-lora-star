/*
 * Copyright (c) 2026 Alexandre Bailon <abailon@baylibre.com>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file frame.h
 * @brief LoRa Star frame encoding and decoding API.
 *
 * Provides helpers to build, parse, and access fields of a LoRa Star frame.
 * A frame is laid out as:
 *
 *   TYPE(1B) | SRC(2B) | DST(2B) | FCNT(4B) | FLAGS(1B) | PAYLOAD(0-114B) | MIC(4B)
 *
 * Callers allocate a buffer (or use ls_frame_alloc()), initialise it with
 * ls_frame_init(), then use the typed accessors to read or write individual
 * fields.  The MIC must be computed over the *encrypted* payload and written
 * last (encrypt-then-MAC).
 */

#ifndef LORA_STAR_LS_FRAME_H
#define LORA_STAR_LS_FRAME_H

#include <stdint.h>
#include <zephyr/sys/util.h>

/**
 * @defgroup lora_star_frame LoRa Star Frame
 * @{
 */

/* Addressing */
#define LS_BCAST_ADDR 0xFFFFU /**< Broadcast address (all nodes) */
#define LS_COORD_ADDR 0x0000U /**< Coordinator address */
#define LS_ADDR_MIN   0x0001U /**< Minimum valid node address */
#define LS_ADDR_MAX   0xFFFEU /**< Maximum valid node address */

/* Frame types */
#define LS_TYPE_JOIN_REQ    0x01U /**< Pairing request from node */
#define LS_TYPE_JOIN_ACCEPT 0x02U /**< Pairing response from coordinator */
#define LS_TYPE_DATA        0x03U /**< Application data frame */
#define LS_TYPE_ACK         0x04U /**< Acknowledgement frame */

/* FLAGS bits */
#define LS_FLAG_ACK_REQ     BIT(0) /**< Sender requests an ACK */
#define LS_FLAG_ACK_PENDING BIT(1) /**< ACK carries a downlink payload */

#define LS_HDR_SIZE      (sizeof(struct ls_frame_hdr)) /**< Fixed header size in bytes */
#define LS_MIC_SIZE      4U                             /**< MIC size in bytes */
#define LS_OVERHEAD_SIZE (LS_HDR_SIZE + LS_MIC_SIZE)
#define LS_MAX_FRAME_SIZE    128U /**< Maximum total frame size in bytes */
#define LS_MAX_PAYLOAD_SIZE  (LS_MAX_FRAME_SIZE - LS_OVERHEAD_SIZE) /**< Maximum application payload size */

/**
 * @brief Compute the total frame size for a given payload length (compile-time macro).
 *
 * @param payload_len Length of the application payload in bytes.
 * @return Total frame size in bytes (header + payload + MIC).
 */
#define LS_FRAME_SIZE(payload_len) (LS_OVERHEAD_SIZE + (payload_len))

/** On-wire frame header (packed, no padding). */
struct ls_frame_hdr {
	uint8_t  type;  /**< Frame type (one of LS_TYPE_*) */
	uint16_t src;   /**< Source address */
	uint16_t dst;   /**< Destination address */
	uint32_t fcnt;  /**< Frame counter (little-endian on wire) */
	uint8_t  flags; /**< Flag bitmask (combination of LS_FLAG_*) */
} __packed;

/** Frame handle that pairs a raw byte buffer with its size. */
struct ls_frame {
	uint8_t *buf;         /**< Pointer to the raw frame buffer */
	size_t   buf_size;    /**< Total size of @p buf in bytes */
	size_t   payload_len; /**< Application payload length in bytes */
	/** RSSI of the received frame in dBm (negative). */
	int8_t   rssi;
};

/**
 * @brief Compute the total frame size for a given payload length.
 *
 * Equivalent to the @ref LS_FRAME_SIZE macro but usable at runtime with a
 * variable length.
 * @param payload_len Length of the application payload in bytes.
 * @return Total frame size in bytes (header + payload + MIC).
 */
size_t ls_frame_size(size_t payload_len);

/**
 * @brief Initialise a frame with an existing buffer.
 *
 * Assigns @p buf to the frame so that the typed accessors can be used.
 * The buffer must be at least ls_frame_size(payload_len) bytes.
 * @param frame    Pointer to the frame to initialise.
 * @param payload_len Length of the application payload in bytes.
 * @param buf      Buffer to use for this frame.
 * @param buf_size Size of @p buf in bytes.
 * @return 0 or -ENOMEM if buffer is too small.
 */
int ls_frame_init(struct ls_frame *frame, size_t payload_len, uint8_t *buf, size_t buf_size);

/**
 * @brief Allocate and initialise a frame on the heap.
 *
 * Allocates a frame struct and a backing buffer large enough to hold a
 * payload of @p payload_len bytes, including the fixed header and MIC.
 * The frame must be released with ls_frame_free() when no longer needed.
 * @param payload_len Length of the application payload in bytes.
 * @return Pointer to the allocated frame, or NULL on allocation failure.
 */
int ls_frame_alloc_buf(struct ls_frame *frame, size_t payload_len);

/**
 * @brief Free a frame allocated by ls_frame_alloc().
 *
 * Releases the backing buffer and the frame struct.  Passing NULL is safe
 * and has no effect.
 * @param frame Pointer to the frame to free.
 */
void ls_frame_free_buf(struct ls_frame *frame);

/**
 * @brief Set the frame type.
 *
 * Valid values are:
 *  - @ref LS_TYPE_JOIN_REQ
 *  - @ref LS_TYPE_JOIN_ACCEPT
 *  - @ref LS_TYPE_DATA
 *  - @ref LS_TYPE_ACK
 * @param frame Pointer to the frame.
 * @param type  Frame type to write.
 */
void ls_frame_set_type(struct ls_frame *frame, uint8_t type);

/**
 * @brief Get the frame type.
 * @param frame Pointer to the frame.
 * @return Frame type (one of the LS_TYPE_* constants).
 */
uint8_t ls_frame_get_type(struct ls_frame *frame);

/**
 * @brief Set the source (emitter) address.
 * @param frame Pointer to the frame.
 * @param src   Address of the frame emitter.
 */
void ls_frame_set_src(struct ls_frame *frame, uint16_t src);

/**
 * @brief Get the source (emitter) address.
 * @param frame Pointer to the frame.
 * @return Address of the frame emitter.
 */
uint16_t ls_frame_get_src(struct ls_frame *frame);

/**
 * @brief Set the destination address.
 *
 * Use @ref LS_COORD_ADDR to address the coordinator, @ref LS_BCAST_ADDR to
 * broadcast, or any value in [@ref LS_ADDR_MIN, @ref LS_ADDR_MAX] for a
 * specific node.
 * @param frame Pointer to the frame.
 * @param dst   Destination address to write.
 */
void ls_frame_set_dst(struct ls_frame *frame, uint16_t dst);

/**
 * @brief Get the destination address.
 * @param frame Pointer to the frame.
 * @return Destination address.
 */
uint16_t ls_frame_get_dst(struct ls_frame *frame);

/**
 * @brief Set the frame counter.
 *
 * The frame counter must be strictly monotonic per sender and must persist
 * across reboots (add @c FCNT_REBOOT_INCREMENT after a restore) to prevent
 * replay attacks.
 * @param frame Pointer to the frame.
 * @param fcnt  Frame counter value to write.
 */
void ls_frame_set_fcnt(struct ls_frame *frame, uint32_t fcnt);

/**
 * @brief Get the frame counter.
 * @param frame Pointer to the frame.
 * @return Frame counter value.
 */
uint32_t ls_frame_get_fcnt(struct ls_frame *frame);

/**
 * @brief Set the frame flags.
 *
 * Accepted flag bits are:
 *  - @ref LS_FLAG_ACK_REQ    — sender requests an acknowledgement
 *  - @ref LS_FLAG_ACK_PENDING — this ACK carries a downlink payload
 * @param frame Pointer to the frame.
 * @param flags Bitmask of flags to write.
 */
void ls_frame_set_flags(struct ls_frame *frame, uint8_t flags);

/**
 * @brief Get the frame flags.
 * @param frame Pointer to the frame.
 * @return Bitmask of flags (combination of LS_FLAG_* constants).
 */
uint8_t ls_frame_get_flags(struct ls_frame *frame);

/**
 * @brief Write the payload into the frame buffer.
 *
 * Copies @c frame->payload_len bytes from @p payload into the payload region
 * of the frame.  The length is fixed at initialisation time; pass a buffer of
 * at least that size.
 * @param frame   Pointer to the frame.
 * @param payload Pointer to the payload data to copy (at least @c frame->payload_len bytes).
 */
void ls_frame_set_payload(struct ls_frame *frame, const uint8_t *payload);

/**
 * @brief Get a pointer to the payload region and its length.
 *
 * Sets @p *payload to the start of the payload within the frame buffer and
 * @p *payload_len to @c frame->payload_len (as recorded at initialisation time).
 * The returned pointer is valid for the lifetime of the frame buffer.
 * @param frame       Pointer to the frame.
 * @param payload     Output: set to the start of the payload in the buffer.
 * @param payload_len Output: set to the payload length in bytes.
 */
void ls_frame_get_payload(struct ls_frame *frame, uint8_t **payload, size_t *payload_len);

/**
 * @brief Write the Message Integrity Code (MIC).
 *
 * The MIC must be computed over the *encrypted* payload (encrypt-then-MAC)
 * and written after encryption is complete.
 * @param frame Pointer to the frame.
 * @param mic   @ref LS_MIC_SIZE-byte buffer containing the MIC to write.
 */
void ls_frame_set_mic(struct ls_frame *frame, const uint8_t mic[LS_MIC_SIZE]);

/**
 * @brief Read the Message Integrity Code (MIC).
 * @param frame Pointer to the frame.
 * @param mic   Output buffer of at least @ref LS_MIC_SIZE bytes to receive
 *              the MIC.
 */
void ls_frame_get_mic(struct ls_frame *frame, uint8_t mic[LS_MIC_SIZE]);

/**
 * @brief Return the size of the frame content (header + payload, excluding MIC).
 *
 * This is the byte range passed to the crypto layer: the payload is encrypted
 * in-place, and the MIC is computed over the encrypted payload immediately
 * after this region.
 * @param frame Pointer to the frame.
 * @return Number of bytes from the start of the buffer up to (but not
 *         including) the MIC.
 */
size_t ls_frame_content_size(struct ls_frame *frame);

/** @} */

#endif /* LORA_STAR_LS_FRAME_H */
