#ifndef LORA_STAR_H
#define LORA_STAR_H

#include <stdint.h>
#include <zephyr/device.h>

/**
 * @file lora_star.h
 * @brief Public API for the LoRa Star protocol library.
 *
 * Build with CONFIG_LORA_STAR=y.  Enable CONFIG_LORA_STAR_COORDINATOR or
 * CONFIG_LORA_STAR_NODE (or both) to include the respective state machine.
 *
 * Typical use:
 *   ls_init(lora_dev);
 *   struct ls_coord_ctx *coord = ls_init_coordinator(lora_dev);
 */

struct ls_coord_ctx; /* coordinator context, returned by ls_init_coordinator() */
struct ls_node_ctx;  /* node context, returned by ls_init_node() */

/* --------------------------------------------------------------------------
 * Common
 * -------------------------------------------------------------------------- */

/**
 * @brief Initialise the LoRa radio and common subsystems (PSA crypto, Settings).
 *
 * Must be called once before ls_init_coordinator() or ls_init_node().
 *
 * @param lora_dev  LoRa radio device (e.g. DEVICE_DT_GET(DT_ALIAS(lora0))).
 * @return 0 on success, negative errno on failure.
 */
int ls_init(const struct device *lora_dev);

/* --------------------------------------------------------------------------
 * Coordinator API
 * -------------------------------------------------------------------------- */

/**
 * @brief Callback invoked on each received uplink.
 *
 * Called from the protocol thread; must not block for long.
 *
 * @param ctx        Coordinator context.
 * @param short_addr Source node address.
 * @param data       Decrypted application payload.
 * @param len        Payload length.
 */
typedef void (*ls_coord_recv_cb)(struct ls_coord_ctx *ctx, uint16_t short_addr,
				 const uint8_t *data, uint8_t len);

/**
 * @brief Callback invoked when a new node completes pairing.
 *
 * @param ctx        Coordinator context.
 * @param short_addr Assigned short address.
 * @param dev_eui    Node DevEUI (8 bytes).
 */
typedef void (*ls_coord_join_cb)(struct ls_coord_ctx *ctx, uint16_t short_addr,
				 const uint8_t *dev_eui);

/**
 * @brief Initialise the coordinator role.
 *
 * Loads persisted node table and frame counter from Settings.
 * Must be called after ls_init().
 *
 * @param lora_dev  LoRa radio device (same one passed to ls_init()).
 * @return Coordinator context on success, NULL on failure.
 */
struct ls_coord_ctx *ls_init_coordinator(const struct device *lora_dev);

/**
 * @brief Enter PAIRING mode for PAIRING_WINDOW_S seconds.
 *
 * Safe to call from any context (submits a k_work item).
 */
void ls_coord_start_pairing(struct ls_coord_ctx *ctx);

/**
 * @brief Queue a downlink payload for a paired node.
 *
 * The payload is buffered and delivered on the next uplink ACK
 * (ACK_PENDING flag).  Only one pending downlink per node is kept;
 * a second call overwrites the first.
 *
 * @param ctx         Coordinator context.
 * @param short_addr  Destination node short address (0x0001–0xFFFE).
 * @param data        Payload buffer (max 114 bytes).
 * @param len         Payload length in bytes.
 * @return 0 on success, -ENOENT if address unknown, -EINVAL if len > 114.
 */
int ls_coord_send(struct ls_coord_ctx *ctx, uint16_t short_addr,
		  const uint8_t *data, uint8_t len);

/** @brief Register the uplink receive callback. */
void ls_coord_set_recv_cb(struct ls_coord_ctx *ctx, ls_coord_recv_cb cb);

/** @brief Register the join (new node paired) callback. */
void ls_coord_set_join_cb(struct ls_coord_ctx *ctx, ls_coord_join_cb cb);

/* --------------------------------------------------------------------------
 * Node API
 * -------------------------------------------------------------------------- */

/**
 * @brief Callback invoked when a downlink is received from the coordinator.
 *
 * Called from the protocol thread; must not block for long.
 *
 * @param ctx   Node context.
 * @param data  Decrypted downlink payload.
 * @param len   Payload length.
 */
typedef void (*ls_node_recv_cb)(struct ls_node_ctx *ctx, const uint8_t *data,
				uint8_t len);

/**
 * @brief Initialise the node role.
 *
 * Reads the DevEUI and loads any persisted session from Settings.
 * Must be called after ls_init().
 *
 * @param lora_dev  LoRa radio device (same one passed to ls_init()).
 * @return Node context on success, NULL on failure.
 */
struct ls_node_ctx *ls_init_node(const struct device *lora_dev);

/**
 * @brief Start the pairing procedure.
 *
 * Broadcasts a JOIN_REQ.  Safe to call from any context.
 */
void ls_node_start_pairing(struct ls_node_ctx *ctx);

/**
 * @brief Send an uplink to the coordinator.
 *
 * Blocking: waits up to (TX_MAX_RETRIES * (RX_WINDOW_MS + TX_RETRY_BACKOFF_MS))
 * for an ACK before returning an error.
 *
 * @param ctx   Node context.
 * @param data  Payload buffer (max 114 bytes).
 * @param len   Payload length.
 * @return 0 on success, or:
 *   -ENOTCONN   node not paired
 *   -EBUSY      previous send still in progress
 *   -EINVAL     len > 114
 *   -ETIMEDOUT  no ACK after all retries
 *   -EACCES     MIC verification failed on received frame
 */
int ls_node_send(struct ls_node_ctx *ctx, const uint8_t *data, uint8_t len);

/** @brief Register the downlink receive callback. */
void ls_node_set_recv_cb(struct ls_node_ctx *ctx, ls_node_recv_cb cb);

#endif /* LORA_STAR_H */
