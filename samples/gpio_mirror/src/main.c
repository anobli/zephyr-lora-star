/*
 * Copyright (c) 2026 Alexandre Bailon <abailon@baylibre.com>
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * gpio_mirror — LoRa Star sample: coordinator mirrors a GPIO state to nodes.
 *
 * Role selection at boot:
 *   SW0 held when reset fires → COORDINATOR
 *   SW0 released (default)   → NODE
 *
 * Coordinator behaviour:
 *   - SW0 (after boot) opens the pairing window.
 *   - SW1 present (and FORCE_PERIODIC=n): broadcasts pin state on every edge.
 *   - SW1 absent or FORCE_PERIODIC=y: broadcasts a counter on a fixed interval.
 *   - Arms a per-node confirmation timeout on every downlink; logs an error
 *     if no confirmation uplink arrives within CONFIRM_TIMEOUT_S seconds.
 *
 * Node behaviour:
 *   - SW0 (after boot) sends a JOIN_REQ.
 *   - On downlink: applies bit 0 to LED0, then immediately wakes the uplink
 *     thread to send a confirmation echoing the applied state.
 *   - 30 s periodic keepalive uplink drains any queued coordinator downlink.
 *
 * Uplink payload (2 bytes):
 *   [0]  MSG_TYPE_KEEPALIVE (0x00) — periodic heartbeat
 *        MSG_TYPE_CONFIRM   (0x01) — state echo after applying a downlink
 *   [1]  sequence counter (keepalive) | applied state (confirm)
 */

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/logging/log.h>
#include <lora_star/lora_star.h>
#include <lora_star/mac.h>
#include <lora_star/coord.h>
#include <lora_star/pairing.h>
#include <lora_star/pairing_button.h>

LOG_MODULE_REGISTER(gpio_mirror, LOG_LEVEL_INF);

#define MSG_TYPE_KEEPALIVE 0x00
#define MSG_TYPE_CONFIRM   0x01

/* -------------------------------------------------------------------------
 * GPIO aliases
 * sw0  — role selector at boot, then repurposed as pairing button
 * sw1  — coordinator signal input (optional)
 * led0 — node mirror output (optional)
 * ------------------------------------------------------------------------- */
static const struct gpio_dt_spec role_btn =
	GPIO_DT_SPEC_GET(DT_ALIAS(sw0), gpios);

#if DT_NODE_EXISTS(DT_ALIAS(sw1))
static const struct gpio_dt_spec signal_btn =
	GPIO_DT_SPEC_GET(DT_ALIAS(sw1), gpios);
#define HAVE_SIGNAL_BTN 1
#else
#define HAVE_SIGNAL_BTN 0
#endif

#if DT_NODE_EXISTS(DT_ALIAS(led0))
static const struct gpio_dt_spec mirror_led =
	GPIO_DT_SPEC_GET(DT_ALIAS(led0), gpios);
#define HAVE_MIRROR_LED 1
#else
#define HAVE_MIRROR_LED 0
#endif

static struct ls_ctx *g_ctx;
static bool           g_is_coord;

/* -------------------------------------------------------------------------
 * Coordinator
 * ------------------------------------------------------------------------- */

#define MAX_NODES 8

struct node_slot {
	uint16_t                addr;
	bool                    has_pending;   /* downlink sent, awaiting confirm */
	uint8_t                 pending_state;
	uint8_t                 retry_count;
	struct k_work_delayable timeout_work;
};

static struct node_slot node_slots[MAX_NODES];
static int              node_count;

/*
 * node_slots is accessed from the protocol thread (join/recv callbacks) and
 * the system workqueue (signal_work_handler, confirm_timeout_handler).
 * In production code this would require a mutex; in a sample the race window
 * is benign since writes and reads never overlap on the same slot field.
 */

static void confirm_timeout_handler(struct k_work *work)
{
	struct node_slot *slot = CONTAINER_OF(k_work_delayable_from_work(work),
					      struct node_slot, timeout_work);
	int ret;

	if (!slot->has_pending) {
		return;
	}

	if (slot->retry_count < CONFIG_LORA_STAR_GPIO_MIRROR_MAX_RETRIES) {
		slot->retry_count++;
		LOG_WRN("Node 0x%04x: no confirmation after %d s "
			"— retrying state 0x%02x (attempt %u/%u)",
			slot->addr,
			CONFIG_LORA_STAR_GPIO_MIRROR_CONFIRM_TIMEOUT_S,
			slot->pending_state,
			slot->retry_count,
			CONFIG_LORA_STAR_GPIO_MIRROR_MAX_RETRIES);

		ret = ls_send_data_async(g_ctx, slot->addr, &slot->pending_state, 1,
					 NULL, NULL);
		if (ret < 0) {
			LOG_WRN("Retry to 0x%04x failed: %d", slot->addr, ret);
		}

		k_work_schedule(&slot->timeout_work,
				K_SECONDS(CONFIG_LORA_STAR_GPIO_MIRROR_CONFIRM_TIMEOUT_S));
	} else {
		LOG_ERR("Node 0x%04x: no confirmation after %d s "
			"— state 0x%02x may not have been applied",
			slot->addr,
			CONFIG_LORA_STAR_GPIO_MIRROR_CONFIRM_TIMEOUT_S,
			slot->pending_state);
		slot->has_pending = false;
	}
}

static void coord_track_node(uint16_t addr)
{
	int i;

	for (i = 0; i < node_count; i++) {
		if (node_slots[i].addr == addr) {
			return;
		}
	}
	if (node_count < MAX_NODES) {
		struct node_slot *slot = &node_slots[node_count++];

		slot->addr        = addr;
		slot->has_pending = false;
		k_work_init_delayable(&slot->timeout_work, confirm_timeout_handler);
		LOG_INF("Tracking node 0x%04x (%d total)", addr, node_count);
	}
}

static void coord_send_state(uint8_t state)
{
	int i;

	if (node_count == 0) {
		if (!ls_is_network_key_set(g_ctx)) {
			LOG_DBG("No paired nodes and no network key — nothing to send");
			return;
		}
		LOG_INF("No paired nodes — broadcasting state 0x%02x via network key",
			state);
		ls_send_data_async(g_ctx, LS_BCAST_ADDR, &state, 1, NULL, NULL);
		return;
	}

	for (i = 0; i < node_count; i++) {
		struct node_slot *slot = &node_slots[i];
		int ret;

		ret = ls_send_data_async(g_ctx, slot->addr, &state, 1, NULL, NULL);

		if (ret < 0) {
			LOG_WRN("Send to 0x%04x failed: %d", slot->addr, ret);
			continue;
		}

		/*
		 * Arm the confirmation timeout for this node.  Use
		 * k_work_schedule (not k_work_reschedule) so that a pending
		 * timeout is never deferred by a subsequent send — otherwise
		 * with PERIOD_S == CONFIRM_TIMEOUT_S the handler never fires.
		 */
		slot->pending_state = state;
		slot->has_pending   = true;
		slot->retry_count   = 0;
		k_work_schedule(&slot->timeout_work,
				K_SECONDS(CONFIG_LORA_STAR_GPIO_MIRROR_CONFIRM_TIMEOUT_S));
	}
}

static void coord_on_join(struct ls_ctx *ls, uint16_t short_addr,
			   const uint8_t dev_eui[LS_DEV_EUI_SIZE], void *user_data)
{
	ARG_UNUSED(ls);
	ARG_UNUSED(user_data);

	LOG_INF("Node joined: addr=0x%04x EUI=%02x%02x%02x%02x%02x%02x%02x%02x",
		short_addr,
		dev_eui[0], dev_eui[1], dev_eui[2], dev_eui[3],
		dev_eui[4], dev_eui[5], dev_eui[6], dev_eui[7]);
	coord_track_node(short_addr);
}

static int coord_on_recv(struct ls_ctx *ls, struct ls_frame *frame, void *user_data)
{
	uint8_t *data;
	size_t payload_len;
	uint16_t addr;
	uint8_t confirmed_state;
	int i;

	ARG_UNUSED(ls);
	ARG_UNUSED(user_data);

	addr = ls_frame_get_src(frame);
	ls_frame_get_payload(frame, &data, &payload_len);

	/* Pick up nodes that re-appear after a coordinator reboot without re-pairing. */
	coord_track_node(addr);

	if (payload_len < 2) {
		LOG_WRN("Short uplink from 0x%04x (%zu byte(s))", addr, payload_len);
		return 0;
	}

	if (data[0] == MSG_TYPE_KEEPALIVE) {
		LOG_DBG("Keepalive from 0x%04x (seq=%u)", addr, data[1]);
		return 0;
	}

	if (data[0] != MSG_TYPE_CONFIRM) {
		LOG_WRN("Unknown uplink type 0x%02x from 0x%04x", data[0], addr);
		return 0;
	}

	confirmed_state = data[1];

	for (i = 0; i < node_count; i++) {
		struct node_slot *slot = &node_slots[i];

		if (slot->addr != addr) {
			continue;
		}

		if (!slot->has_pending) {
			LOG_DBG("Stale confirm from 0x%04x (state=0x%02x)",
				addr, confirmed_state);
			return 0;
		}

		k_work_cancel_delayable(&slot->timeout_work);
		slot->has_pending = false;

		if (confirmed_state == slot->pending_state) {
			LOG_INF("Node 0x%04x confirmed state 0x%02x OK",
				addr, confirmed_state);
		} else {
			LOG_ERR("Node 0x%04x state mismatch: sent 0x%02x, got 0x%02x",
				addr, slot->pending_state, confirmed_state);
		}
		return 0;
	}

	return 0;
}

/* -- SW1 signal (optional) -- */

#if HAVE_SIGNAL_BTN && !IS_ENABLED(CONFIG_LORA_STAR_GPIO_MIRROR_FORCE_PERIODIC)

static struct gpio_callback signal_btn_cb;
static struct k_work        signal_work;

static void signal_work_handler(struct k_work *work)
{
	int state = gpio_pin_get_dt(&signal_btn);

	ARG_UNUSED(work);

	LOG_INF("SW1 edge → state=%d, broadcasting to %d node(s)", state, node_count);
	coord_send_state((uint8_t)(state & 0x01));
}

static void signal_isr(const struct device *dev, struct gpio_callback *cb,
			uint32_t pins)
{
	ARG_UNUSED(dev);
	ARG_UNUSED(cb);
	ARG_UNUSED(pins);
	k_work_submit(&signal_work);
}

static void coord_signal_init(void)
{
	k_work_init(&signal_work, signal_work_handler);

	if (!device_is_ready(signal_btn.port)) {
		LOG_WRN("SW1 GPIO port not ready");
		return;
	}
	gpio_pin_configure_dt(&signal_btn, GPIO_INPUT);
	gpio_pin_interrupt_configure_dt(&signal_btn, GPIO_INT_EDGE_BOTH);
	gpio_init_callback(&signal_btn_cb, signal_isr, BIT(signal_btn.pin));
	gpio_add_callback(signal_btn.port, &signal_btn_cb);
	LOG_INF("SW1 ready — coordinator will broadcast on every edge");
}

#else /* !(HAVE_SIGNAL_BTN && !FORCE_PERIODIC) */

static struct k_work_delayable signal_work;

static void signal_work_handler(struct k_work *work)
{
	static uint8_t tick;

	ARG_UNUSED(work);

	LOG_INF("Periodic tick %u — broadcasting to %d node(s)", tick, node_count);
	coord_send_state((tick++) % 2);
	k_work_schedule(&signal_work, K_SECONDS(CONFIG_LORA_STAR_GPIO_MIRROR_PERIOD_S));
}

static void coord_signal_init(void)
{
	k_work_init_delayable(&signal_work, signal_work_handler);
	k_work_schedule(&signal_work, K_SECONDS(CONFIG_LORA_STAR_GPIO_MIRROR_PERIOD_S));
	LOG_INF("Periodic mode — broadcasting every %d s",
		CONFIG_LORA_STAR_GPIO_MIRROR_PERIOD_S);
}

#endif /* HAVE_SIGNAL_BTN && !FORCE_PERIODIC */

static int coord_init(const struct device *lora_dev)
{
	int ret;

	g_ctx = ls_init(lora_dev);
	if (!g_ctx) {
		LOG_ERR("ls_init failed");
		return -EIO;
	}

	ret = ls_init_coord(g_ctx);
	if (ret < 0) {
		LOG_ERR("ls_init_coord failed: %d", ret);
		return ret;
	}

	ls_pairing_button_set_join_cb(coord_on_join, NULL);

	ls_register_data_cb(g_ctx, LS_BCAST_ADDR, coord_on_recv, NULL);

	coord_signal_init();
	return 0;
}

/* -------------------------------------------------------------------------
 * Node
 * ------------------------------------------------------------------------- */

static struct k_work_delayable node_keepalive_work;
static uint8_t                 node_keepalive_seq;

static void on_uplink_done(int ret, void *user_data)
{
	ARG_UNUSED(user_data);

	if (ret == -ETIMEDOUT) {
		LOG_WRN("Uplink timed out (no ACK)");
	} else if (ret < 0) {
		LOG_WRN("Uplink failed: %d", ret);
	}
	k_work_schedule(&node_keepalive_work, K_SECONDS(30));
}

static void node_keepalive_work_fn(struct k_work *work)
{
	uint8_t uplink[2];

	ARG_UNUSED(work);

	if (!ls_is_paired(g_ctx)) {
		k_work_schedule(&node_keepalive_work, K_SECONDS(30));
		return;
	}

	uplink[0] = MSG_TYPE_KEEPALIVE;
	uplink[1] = node_keepalive_seq++;
	ls_send_data_ack_async(g_ctx, LS_COORD_ADDR, uplink, sizeof(uplink),
			       on_uplink_done, NULL);
}

static int node_on_recv(struct ls_ctx *ls, struct ls_frame *frame, void *user_data)
{
	uint8_t *data;
	uint8_t uplink[2];
	size_t payload_len;
	uint8_t state;

	ARG_UNUSED(ls);
	ARG_UNUSED(user_data);

	ls_frame_get_payload(frame, &data, &payload_len);

	if (payload_len == 0) {
		return 0;
	}

	state = data[0];

	LOG_INF("Downlink: state=0x%02x", state);

#if HAVE_MIRROR_LED
	gpio_pin_set_dt(&mirror_led, state & 0x01);
	LOG_INF("LED0 → %s", (state & 0x01) ? "ON" : "OFF");
#endif

	k_work_cancel_delayable(&node_keepalive_work);
	uplink[0] = MSG_TYPE_CONFIRM;
	uplink[1] = state;
	ls_send_data_ack_async(g_ctx, LS_COORD_ADDR, uplink, sizeof(uplink),
			       on_uplink_done, NULL);

	return 0;
}

static void node_pairing_done(struct ls_ctx *ctx, int result, void *user_data)
{
	ARG_UNUSED(ctx);
	ARG_UNUSED(user_data);

	if (result < 0) {
		LOG_WRN("Pairing failed: %d", result);
	} else {
		LOG_INF("Pairing succeeded — node is now connected");
	}
}

static int node_init(const struct device *lora_dev)
{
	g_ctx = ls_init(lora_dev);
	if (!g_ctx) {
		LOG_ERR("ls_init failed");
		return -EIO;
	}

	ls_pairing_button_set_done_cb(node_pairing_done, NULL);

	ls_register_data_cb(g_ctx, LS_BCAST_ADDR, node_on_recv, NULL);

#if HAVE_MIRROR_LED
	if (device_is_ready(mirror_led.port)) {
		gpio_pin_configure_dt(&mirror_led, GPIO_OUTPUT_INACTIVE);
		LOG_INF("LED0 ready — will mirror coordinator signal");
	} else {
		LOG_WRN("LED0 not available");
	}
#endif

	k_work_init_delayable(&node_keepalive_work, node_keepalive_work_fn);
	k_work_schedule(&node_keepalive_work, K_SECONDS(30));

	return 0;
}

/* -------------------------------------------------------------------------
 * Main
 * ------------------------------------------------------------------------- */

int main(void)
{
	const struct device *lora_dev = DEVICE_DT_GET(DT_ALIAS(lora0));
	int ret;

	/*
	 * Role selection: sample SW0 during early boot.
	 * Hold SW0 at reset → coordinator.  Release (default) → node.
	 */
	g_is_coord = false;

	if (device_is_ready(role_btn.port)) {
		gpio_pin_configure_dt(&role_btn, GPIO_INPUT);
		k_sleep(K_MSEC(50)); /* let pin settle */
		g_is_coord = gpio_pin_get_dt(&role_btn) > 0;
	}

	LOG_INF("Role: %s (SW0 sampled as %s)",
		g_is_coord ? "COORDINATOR" : "NODE",
		g_is_coord ? "active" : "inactive");

	/* Tell the pairing-button driver which role to trigger on press. */
	ls_pairing_button_set_role(g_is_coord);

	ret = g_is_coord ? coord_init(lora_dev) : node_init(lora_dev);
	if (ret < 0) {
		return ret;
	}

	LOG_INF("gpio_mirror ready");
	return 0;
}
