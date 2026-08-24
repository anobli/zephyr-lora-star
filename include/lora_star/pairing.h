/*
 * Copyright (c) 2026 Alexandre Bailon <abailon@baylibre.com>
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LORA_STAR_PAIRING_H
#define LORA_STAR_PAIRING_H

#include <stdint.h>
#include <zephyr/kernel.h>
#include <lora_star/lora_star.h>
#include <lora_star/frame.h>

/* Pairing field sizes */
#define LS_PUBKEY_SIZE   32U /**< Curve25519 public/private key length in bytes */
#define LS_NONCE_SIZE    4U  /**< Pairing nonce length in bytes */

/** JOIN_REQ payload: DevEUI(8) + NodePubKey(32) + Nonce(4) = 44 bytes */
#define LS_JOIN_REQ_PAYLOAD_SIZE (LS_DEV_EUI_SIZE + LS_PUBKEY_SIZE + LS_NONCE_SIZE)

/**
 * @brief Wire format of the JOIN_REQ payload.
 *
 * Broadcast by the node during pairing.  Contains everything the coordinator
 * needs to derive the session key and assign a short address.
 */
struct ls_join_req_payload {
	/** Device EUI — uniquely identifies the node across pairing sessions. */
	uint8_t dev_eui[LS_DEV_EUI_SIZE];
	/** Ephemeral Curve25519 public key for ECDH key exchange. */
	uint8_t node_pub_key[LS_PUBKEY_SIZE];
	/** Random nonce — binds the session key to this specific pairing attempt. */
	uint8_t nonce[LS_NONCE_SIZE];
} __packed;

/**
 * @brief Wire format of the JOIN_ACCEPT payload.
 *
 * Sent by the coordinator after a valid JOIN_REQ.  Contains the coordinator's
 * ECDH public key (needed by the node to derive the shared secret) and an
 * encrypted blob holding the assigned short address and the network key.
 * Only the node that sent the JOIN_REQ can decrypt the blob, because the
 * pairing key is derived from the ECDH shared secret and the node's nonce.
 */
struct ls_join_accept_payload {
	/** Ephemeral Curve25519 public key for ECDH key exchange. */
	uint8_t coord_pub_key[LS_PUBKEY_SIZE];
	/**
	 * AES-128-CTR(pairing_key, Nonce||0x00…, short_addr_LE(2) || network_key(16)).
	 * Decrypted by the node to recover its assigned address and the shared network key.
	 */
	uint8_t enc_payload[sizeof(uint16_t) + LS_NETWORK_KEY_SIZE];
} __packed;

/** Total size of the JOIN_ACCEPT payload on the wire (32 + 2 + 16 = 50 bytes). */
#define LS_JOIN_ACCEPT_PAYLOAD_SIZE \
	(LS_PUBKEY_SIZE + sizeof(uint16_t) + LS_NETWORK_KEY_SIZE)

/* --------------------------------------------------------------------------
 * Coordinator side
 * -------------------------------------------------------------------------- */

#ifdef CONFIG_LORA_STAR_COORDINATOR

/**
 * @brief Callback invoked when a node successfully completes pairing.
 *
 * Called from the LoRa Star thread after JOIN_ACCEPT has been transmitted and
 * the node record has been persisted to storage.
 *
 * @param ctx        LoRa Star context.
 * @param short_addr ShortAddr assigned to the new (or re-paired) node.
 * @param dev_eui    Node DevEUI (8 bytes).  Valid only for the duration of the call.
 * @param user_data  Opaque pointer supplied at @ref ls_pairing_coord_init() time.
 */
typedef void (*ls_pairing_join_cb)(struct ls_ctx *ctx, uint16_t short_addr,
				   const uint8_t dev_eui[LS_DEV_EUI_SIZE],
				   void *user_data);

/**
 * @brief Coordinator-side pairing context.
 *
 * Owns the node table, address allocator, and ephemeral ECDH state for the
 * current pairing window.  Allocated and held by the coordinator application;
 * pass it to @ref ls_pairing_coord_init() then @ref ls_pairing_coord_start().
 *
 * The @c nodes array and @c next_addr field are readable by the coordinator
 * application for data-path lookups after pairing completes.
 */
struct ls_coord_pairing_ctx {
	/** Node table (index = slot; may be read by coordinator app). */
	struct coord_node nodes[CONFIG_LORA_STAR_MAX_NODES];
	/** Next ShortAddr to assign; starts at LS_ADDR_MIN after init. */
	uint16_t          next_addr;

	/** @cond INTERNAL */
	bool                    _pairing_open;
	uint8_t                 _priv_key[LS_PUBKEY_SIZE];
	uint8_t                 _pub_key[LS_PUBKEY_SIZE];
	struct k_work_delayable _close_work;
	struct ls_frame_handler *_join_req_hdl;
	ls_pairing_join_cb      _join_cb;
	void                   *_join_cb_ud;
	struct ls_ctx          *_ctx;
	/** @endcond */
};

/**
 * @brief Initialize coordinator pairing context and load persistent node state.
 *
 * Restores next_addr and per-node records from Settings.  Also loads the
 * coordinator's own FCNT from storage and writes it back with
 * @c CONFIG_LORA_STAR_FCNT_REBOOT_INCREMENT added as a reboot guard.
 *
 * @note @c ls_storage_init() is called internally; the Settings subsystem
 *       must have been initialized (e.g. via @c settings_subsys_init()) before
 *       this call.
 *
 * @param ctx        LoRa Star context (owns the coordinator FCNT).
 * @param pair_ctx   Pairing context to initialize; zeroed and populated.
 * @param cb         Called when a node completes pairing; may be NULL.
 * @param user_data  Forwarded to @p cb.
 * @return 0 on success, negative errno on storage failure.
 */
int ls_pairing_coord_init(struct ls_ctx *ctx, struct ls_coord_pairing_ctx *pair_ctx,
			  ls_pairing_join_cb cb, void *user_data);

/**
 * @brief Open the pairing window.
 *
 * Generates an ephemeral ECDH keypair, registers a JOIN_REQ frame handler,
 * and schedules the @c CONFIG_LORA_STAR_PAIRING_WINDOW_S auto-close timer.
 * The window closes automatically after the first successful join or when the
 * timer fires.  Call @ref ls_pairing_coord_start() again to re-open.
 *
 * @param pair_ctx Coordinator pairing context (must have been initialized with
 *                 @ref ls_pairing_coord_init()).
 * @return 0 on success, -ENOMEM if the frame callback registry is full,
 *         negative errno on ECDH failure.
 */
int ls_pairing_coord_start(struct ls_coord_pairing_ctx *pair_ctx);

#endif /* CONFIG_LORA_STAR_COORDINATOR */

/* --------------------------------------------------------------------------
 * Node side
 * -------------------------------------------------------------------------- */

#ifdef CONFIG_LORA_STAR_NODE

/**
 * @brief Callback invoked when node pairing completes (success or failure).
 *
 * Called from the internal pairing thread, not from the LoRa Star protocol
 * thread.  The result is 0 on success, -ETIMEDOUT if all retries were
 * exhausted, or another negative errno on hard failure.
 *
 * @param ctx       LoRa Star context.
 * @param result    0 on success, negative errno on failure.
 * @param user_data Opaque pointer supplied in @ref ls_node_pairing_ctx.
 */
typedef void (*ls_pairing_node_done_cb)(struct ls_ctx *ctx, int result,
					void *user_data);

/**
 * @brief Node-side pairing context.
 *
 * The caller must populate @c dev_eui (e.g. via @c hwinfo_get_device_id())
 * and optionally @c done_cb / @c done_user_data before calling
 * @ref ls_pairing_node_start().  All other fields are managed internally.
 */
struct ls_node_pairing_ctx {
	/** Device EUI — caller fills this in before ls_pairing_node_start(). */
	uint8_t dev_eui[LS_DEV_EUI_SIZE];
	/** Called when pairing finishes; may be NULL. */
	ls_pairing_node_done_cb done_cb;
	/** Forwarded to @p done_cb. */
	void *done_user_data;

	/** @cond INTERNAL */
	struct ls_ctx           *_ctx;
	uint8_t                  _priv_key[LS_PUBKEY_SIZE];
	uint8_t                  _pub_key[LS_PUBKEY_SIZE];
	uint8_t                  _nonce[LS_NONCE_SIZE];
	struct k_sem             _done_sem;
	int                      _result;
	struct ls_frame_handler *_join_accept_hdl;
	/** @endcond */
};

/**
 * @brief Start node pairing asynchronously.
 *
 * Submits the pairing sequence to the internal TX thread and returns
 * immediately.  The sequence generates an ephemeral ECDH keypair, broadcasts
 * a JOIN_REQ, and waits for a valid JOIN_ACCEPT.  On success it calls
 * @ref ls_set_network_key() and @ref ls_set_own_addr() on @p ctx and persists
 * the session to Settings.  Retries up to @c CONFIG_LORA_STAR_TX_MAX_RETRIES
 * times with backoff.
 *
 * The result is delivered via @c pair_ctx->done_cb (if non-NULL) from the
 * TX thread context.
 *
 * @pre @c pair_ctx->dev_eui must be filled in by the caller.
 * @pre @ref ls_init() must have been called first.
 *
 * @param ctx      LoRa Star context.
 * @param pair_ctx Node pairing context.
 * @return 0 if the pairing work was submitted, negative errno on error.
 */
int ls_pairing_node_start(struct ls_ctx *ctx, struct ls_node_pairing_ctx *pair_ctx);

#endif /* CONFIG_LORA_STAR_NODE */

#endif /* LORA_STAR_PAIRING_H */
