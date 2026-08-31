/*
 * Copyright (c) 2026 Alexandre Bailon <abailon@baylibre.com>
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * link_test — LoRa Star reliability test: coordinator periodically pings a
 * node with ACK_REQ frames and tracks delivery statistics.
 *
 * Role is selected at build time:
 *   CONFIG_LORA_STAR_LINK_TEST_COORDINATOR=y  →  sends DATA + tracks stats
 *   CONFIG_LORA_STAR_LINK_TEST_NODE=y          →  ACKs every DATA received
 *
 * Both roles use the devicetree-configured pairing button (SW0) to trigger
 * pairing; see subsys/lora_star/pairing_button.c.
 *
 * Coordinator behaviour:
 *   Every PERIOD_S, sends a DATA frame with ACK_REQ to the paired node.  On
 *   timeout the application retries up to MAX_RETRIES times (the LoRa Star
 *   stack has TX_MAX_RETRIES=0 so every attempt is visible here).  Every
 *   STATS_S the coordinator logs lifetime error% and retry%.
 *
 * Node behaviour:
 *   Stays in continuous RX.  Calls ls_send_ack() for every DATA frame
 *   carrying LS_FLAG_ACK_REQ, and toggles led0 (if present) on every DATA
 *   frame received — a visual "still in range" indicator for range testing
 *   without a serial console.
 *
 * Statistics definitions (coordinator only):
 *   sent   — distinct packets initiated (retries of the same packet are not
 *             counted again here)
 *   errors — packets that were lost after all retry attempts
 *   retried — packets that needed at least one retry (but may still have
 *              been delivered eventually)
 *   error%  = errors  * 100 / sent
 *   retry%  = retried * 100 / sent
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

LOG_MODULE_REGISTER(link_test, LOG_LEVEL_INF);

static struct ls_ctx *g_ctx;

/* -------------------------------------------------------------------------
 * Coordinator
 * ------------------------------------------------------------------------- */

#if IS_ENABLED(CONFIG_LORA_STAR_LINK_TEST_COORDINATOR)

/*
 * LS_BCAST_ADDR is used as a sentinel meaning "no node paired yet".
 * Node addresses are in [LS_ADDR_MIN, LS_ADDR_MAX] so 0xFFFF is never valid.
 */
static uint16_t g_node_addr = LS_BCAST_ADDR;

static struct {
	uint32_t sent;        /* new packets initiated */
	uint32_t errors;      /* packets lost after all retries */
	uint32_t retried;     /* packets needing at least one retry */
	uint8_t  cur_retries; /* retry count for the current in-flight packet */
} g_stats;

static struct k_work_delayable g_send_work;
static struct k_work           g_retry_work;
static struct k_work_delayable g_stats_work;

static void send_packet(void);

static void on_send_done(int ret, void *user_data)
{
	ARG_UNUSED(user_data);

	if (ret == 0) {
		k_work_schedule(&g_send_work,
				K_SECONDS(CONFIG_LORA_STAR_LINK_TEST_PERIOD_S));
	} else {
		k_work_submit(&g_retry_work);
	}
}

static void send_packet(void)
{
	uint8_t data[2];
	int ret;

	data[0] = (uint8_t)(g_stats.sent & 0xFF);
	data[1] = g_stats.cur_retries;

	ret = ls_send_data_ack_async(g_ctx, g_node_addr, data, sizeof(data),
				     on_send_done, NULL);
	if (ret < 0) {
		LOG_WRN("Enqueue failed: %d — rescheduling", ret);
		k_work_schedule(&g_send_work, K_SECONDS(1));
	}
}

static void retry_work_fn(struct k_work *work)
{
	ARG_UNUSED(work);

	/*
	 * Increment retried once per packet (not once per retry attempt) so
	 * the counter reflects packets that needed help, not total attempts.
	 */
	if (g_stats.cur_retries == 0) {
		g_stats.retried++;
	}
	g_stats.cur_retries++;

	if (g_stats.cur_retries <= CONFIG_LORA_STAR_LINK_TEST_MAX_RETRIES) {
		LOG_WRN("Packet 0x%02x: retry %u/%u",
			(uint8_t)(g_stats.sent & 0xFF),
			g_stats.cur_retries,
			CONFIG_LORA_STAR_LINK_TEST_MAX_RETRIES);
		send_packet();
	} else {
		g_stats.errors++;
		LOG_ERR("Packet 0x%02x: lost after %d retries",
			(uint8_t)(g_stats.sent & 0xFF),
			CONFIG_LORA_STAR_LINK_TEST_MAX_RETRIES);
		k_work_schedule(&g_send_work,
				K_SECONDS(CONFIG_LORA_STAR_LINK_TEST_PERIOD_S));
	}
}

static void send_work_fn(struct k_work *work)
{
	ARG_UNUSED(work);

	if (g_node_addr == LS_BCAST_ADDR) {
		/* No node paired yet; poll until one joins. */
		k_work_schedule(&g_send_work, K_SECONDS(1));
		return;
	}

	g_stats.sent++;
	g_stats.cur_retries = 0;
	send_packet();
}

static void stats_work_fn(struct k_work *work)
{
	uint32_t sent    = g_stats.sent;
	uint32_t errors  = g_stats.errors;
	uint32_t retried = g_stats.retried;

	ARG_UNUSED(work);

	if (sent == 0) {
		LOG_INF("link_test stats: no packets sent yet");
	} else {
		LOG_INF("link_test stats: sent=%u  error=%u (%u%%)  retry=%u (%u%%)",
			sent,
			errors,  errors  * 100U / sent,
			retried, retried * 100U / sent);
	}

	k_work_schedule(&g_stats_work,
			K_SECONDS(CONFIG_LORA_STAR_LINK_TEST_STATS_S));
}

static void coord_on_join(struct ls_ctx *ls, uint16_t short_addr,
			   const uint8_t dev_eui[LS_DEV_EUI_SIZE],
			   void *user_data)
{
	ARG_UNUSED(ls);
	ARG_UNUSED(user_data);

	LOG_INF("Node joined: addr=0x%04x EUI=%02x%02x%02x%02x%02x%02x%02x%02x",
		short_addr,
		dev_eui[0], dev_eui[1], dev_eui[2], dev_eui[3],
		dev_eui[4], dev_eui[5], dev_eui[6], dev_eui[7]);

	if (g_node_addr == LS_BCAST_ADDR) {
		g_node_addr = short_addr;
		LOG_INF("P2P peer set to 0x%04x — link test active", g_node_addr);
	} else {
		LOG_WRN("Second node 0x%04x ignored (P2P mode; only one peer supported)",
			short_addr);
	}
}

static int coord_init(const struct device *lora_dev)
{
	struct ls_coord_ctx *coord;
	int i;
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

	/* Restore peer address from a previous session if available. */
	coord = ls_coord_get();
	for (i = 0; i < CONFIG_LORA_STAR_MAX_NODES; i++) {
		if (coord->nodes[i].active) {
			g_node_addr = coord->nodes[i].short_addr;
			LOG_INF("Restored peer 0x%04x from storage — link test active",
				g_node_addr);
			break;
		}
	}

	k_work_init(&g_retry_work, retry_work_fn);
	k_work_init_delayable(&g_send_work, send_work_fn);
	k_work_init_delayable(&g_stats_work, stats_work_fn);

	k_work_schedule(&g_send_work,
			K_SECONDS(CONFIG_LORA_STAR_LINK_TEST_PERIOD_S));
	k_work_schedule(&g_stats_work,
			K_SECONDS(CONFIG_LORA_STAR_LINK_TEST_STATS_S));

	return 0;
}

#endif /* CONFIG_LORA_STAR_LINK_TEST_COORDINATOR */

/* -------------------------------------------------------------------------
 * Node
 * ------------------------------------------------------------------------- */

#if IS_ENABLED(CONFIG_LORA_STAR_LINK_TEST_NODE)

#if DT_NODE_EXISTS(DT_ALIAS(led0))
static const struct gpio_dt_spec status_led = GPIO_DT_SPEC_GET(DT_ALIAS(led0), gpios);
#define HAVE_STATUS_LED 1
#else
#define HAVE_STATUS_LED 0
#endif

static void node_pairing_done(struct ls_ctx *ctx, int result, void *user_data)
{
	ARG_UNUSED(ctx);
	ARG_UNUSED(user_data);

	if (result < 0) {
		LOG_WRN("Pairing failed: %d", result);
	} else {
		LOG_INF("Pairing succeeded");
	}
}

static int node_on_recv(struct ls_ctx *ctx, struct ls_frame *frame,
			void *user_data)
{
	uint8_t flags;

	ARG_UNUSED(user_data);

	flags = ls_frame_get_flags(frame);
	if (flags & LS_FLAG_ACK_REQ) {
		ls_send_ack(ctx, ls_frame_get_src(frame));
	}

#if HAVE_STATUS_LED
	gpio_pin_toggle_dt(&status_led);
#endif

	return 0;
}

static int node_init(const struct device *lora_dev)
{
	g_ctx = ls_init(lora_dev);
	if (!g_ctx) {
		LOG_ERR("ls_init failed");
		return -EIO;
	}

	ls_pairing_button_set_done_cb(node_pairing_done, NULL);

#if HAVE_STATUS_LED
	if (device_is_ready(status_led.port)) {
		gpio_pin_configure_dt(&status_led, GPIO_OUTPUT_INACTIVE);
		LOG_INF("led0 ready — will toggle on every received frame");
	} else {
		LOG_WRN("led0 not ready");
	}
#else
	LOG_INF("led0 not available on this board — no RX indicator");
#endif

	/*
	 * The node stays in continuous RX so it can receive coordinator
	 * downlinks at any time.  ls_mac_send() (called by ls_send_ack())
	 * automatically stops and restarts RX around each transmission
	 * because always_on_rx is true.
	 */
	g_ctx->always_on_rx = true;
	ls_register_data_cb(g_ctx, LS_BCAST_ADDR, node_on_recv, NULL);
	ls_mac_recv(g_ctx);

	return 0;
}

#endif /* CONFIG_LORA_STAR_LINK_TEST_NODE */

/* -------------------------------------------------------------------------
 * Main
 * ------------------------------------------------------------------------- */

int main(void)
{
	const struct device *lora_dev = DEVICE_DT_GET(DT_ALIAS(lora0));
	int ret;

	LOG_INF("link_test starting as %s",
		IS_ENABLED(CONFIG_LORA_STAR_LINK_TEST_COORDINATOR)
		? "COORDINATOR" : "NODE");

	/* Tell the pairing-button driver which role to trigger on press. */
	ls_pairing_button_set_role(IS_ENABLED(CONFIG_LORA_STAR_LINK_TEST_COORDINATOR));

#if IS_ENABLED(CONFIG_LORA_STAR_LINK_TEST_COORDINATOR)
	ret = coord_init(lora_dev);
#else
	ret = node_init(lora_dev);
#endif
	if (ret < 0) {
		return ret;
	}

	LOG_INF("link_test ready");
	return 0;
}
