#ifndef LS_INTERNAL_H
#define LS_INTERNAL_H

#include <stdint.h>
#include <zephyr/kernel.h>
#include <zephyr/drivers/lora.h>
#include <lora_star/lora_star.h>
#include <lora_star/ls_frame.h>

/* --------------------------------------------------------------------------
 * Common helpers
 * -------------------------------------------------------------------------- */

int ls_append_mic(uint8_t *buf, uint8_t hdr_payload_len, const uint8_t *key);

/* --------------------------------------------------------------------------
 * Coordinator
 * -------------------------------------------------------------------------- */

#if defined(CONFIG_LORA_STAR_COORDINATOR)

enum coord_state {
	COORD_IDLE,
	COORD_PAIRING,
};

struct coord_node {
	uint16_t              short_addr;
	struct ls_node_record rec;
	bool                  active;
};

struct downlink_entry {
	uint8_t data[LS_MAX_PAYLOAD_SIZE];
	uint8_t len;
	bool    pending;
};

struct coord_rx_frame {
	uint8_t data[LS_MAX_FRAME_SIZE];
	uint8_t len;
	int16_t rssi;
};

struct ls_coord_ctx {
	const struct device    *lora_dev;
	enum coord_state        state;
	ls_coord_recv_cb        recv_cb;
	ls_coord_join_cb        join_cb;
	uint16_t                next_addr;
	uint32_t                fcnt;
	uint8_t                 priv_key[LS_PUBKEY_SIZE];
	uint8_t                 pub_key[LS_PUBKEY_SIZE];
	bool                    keypair_ready;
	struct coord_node       nodes[CONFIG_LORA_STAR_MAX_NODES];
	struct downlink_entry   downlinks[CONFIG_LORA_STAR_MAX_NODES];
	struct k_mutex          dl_mutex;
	struct k_work           pairing_work;
	struct k_work_delayable pairing_close_work;
	struct k_msgq           rx_msgq;
	struct lora_modem_config radio_cfg;
};

#endif /* CONFIG_LORA_STAR_COORDINATOR */

/* --------------------------------------------------------------------------
 * Node
 * -------------------------------------------------------------------------- */

#if defined(CONFIG_LORA_STAR_NODE)

enum node_state {
	NODE_UNJOINED,
	NODE_JOINING,
	NODE_JOINED,
	NODE_WAITING_ACK,
};

struct ls_node_ctx {
	const struct device     *lora_dev;
	enum node_state          state;
	ls_node_recv_cb          recv_cb;
	uint8_t                  dev_eui[LS_DEV_EUI_SIZE];
	uint16_t                 short_addr;
	uint8_t                  session_key[LS_SESSION_KEY_SIZE];
	uint32_t                 own_fcnt;
	uint32_t                 fcnt_last;
	uint8_t                  priv_key[LS_PUBKEY_SIZE];
	uint8_t                  pub_key[LS_PUBKEY_SIZE];
	uint8_t                  join_nonce[LS_NONCE_SIZE];
	uint8_t                  pending_data[LS_MAX_PAYLOAD_SIZE];
	uint8_t                  pending_len;
	uint8_t                  retry_count;
	int                      send_result;
	struct k_sem             pairing_sem;
	struct k_sem             send_sem;
	struct k_sem             result_sem;
	struct k_mutex           send_lock;
	struct k_work            pairing_work;
	struct lora_modem_config radio_cfg;
};

#endif /* CONFIG_LORA_STAR_NODE */

#endif /* LS_INTERNAL_H */
