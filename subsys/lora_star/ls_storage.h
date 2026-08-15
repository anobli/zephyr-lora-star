#ifndef LS_STORAGE_H
#define LS_STORAGE_H

#include <stdint.h>
#include <lora_star/ls_frame.h>

/**
 * Initialise the Settings subsystem and register the LoRa Star handlers.
 * Must be called once, before ls_storage_coord_load() or ls_storage_node_load().
 */
int ls_storage_init(void);

/* --------------------------------------------------------------------------
 * Coordinator
 * -------------------------------------------------------------------------- */

/**
 * Callback invoked for each node record found in Settings during coordinator
 * startup.  The coordinator state machine registers this to populate its
 * in-RAM node table.
 */
typedef void (*ls_storage_node_load_cb)(uint16_t short_addr,
					const struct ls_node_record *rec,
					void *user_data);

/**
 * Load coordinator persistent state.
 *
 * @param next_addr  Receives the next ShortAddr to assign (defaults to 0x0001).
 * @param fcnt       Receives the coordinator's own FCNT (defaults to 0).
 * @param node_cb    Called for every persisted node record; may be NULL.
 * @param user_data  Forwarded to node_cb.
 */
int ls_storage_coord_load(uint16_t *next_addr, uint32_t *fcnt,
			  ls_storage_node_load_cb node_cb, void *user_data);

int ls_storage_coord_save_next_addr(uint16_t next_addr);
int ls_storage_coord_save_fcnt(uint32_t fcnt);
int ls_storage_coord_save_node(uint16_t short_addr, const struct ls_node_record *rec);

/* --------------------------------------------------------------------------
 * Node
 * -------------------------------------------------------------------------- */

/**
 * Load node persistent state.
 *
 * @return 0 if a valid session was found, -ENOENT if the node has never paired.
 */
int ls_storage_node_load(uint16_t *short_addr,
			 uint8_t session_key[LS_SESSION_KEY_SIZE],
			 uint32_t *own_fcnt, uint32_t *fcnt_last);

int ls_storage_node_save(uint16_t short_addr,
			 const uint8_t session_key[LS_SESSION_KEY_SIZE],
			 uint32_t own_fcnt);

int ls_storage_node_save_fcnt(uint32_t own_fcnt);
int ls_storage_node_save_fcnt_last(uint32_t fcnt_last);

#endif /* LS_STORAGE_H */
