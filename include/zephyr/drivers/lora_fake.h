/*
 * Copyright (c) 2026 Alexandre Bailon <abailon@baylibre.com>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file lora_fake.h
 * @brief fff-based fake of the Zephyr LoRa driver API, for unit tests.
 *
 * Include this header in test files; link against drivers/lora/lora_fake.c.
 * lora_fake.c already calls DEFINE_FFF_GLOBALS — do not repeat it.
 */

#pragma once

#include <zephyr/fff.h>
#include <zephyr/drivers/lora.h>

/** Fake for @c lora_driver_api::config. */
DECLARE_FAKE_VALUE_FUNC(int, lora_fake_config,
			const struct device *, const struct lora_modem_config *);

/** Fake for @c lora_driver_api::airtime. */
DECLARE_FAKE_VALUE_FUNC(uint32_t, lora_fake_airtime,
			const struct device *, uint32_t);

/** Fake for @c lora_driver_api::send. */
DECLARE_FAKE_VALUE_FUNC(int, lora_fake_send,
			const struct device *, uint8_t *, uint32_t);

/** Fake for @c lora_driver_api::send_async. */
DECLARE_FAKE_VALUE_FUNC(int, lora_fake_send_async,
			const struct device *, uint8_t *, uint32_t,
			struct k_poll_signal *);

/** Fake for @c lora_driver_api::recv. */
DECLARE_FAKE_VALUE_FUNC(int, lora_fake_recv,
			const struct device *, uint8_t *, uint8_t,
			k_timeout_t, int16_t *, int8_t *);

/** Fake for @c lora_driver_api::recv_async. */
DECLARE_FAKE_VALUE_FUNC(int, lora_fake_recv_async,
			const struct device *, lora_recv_cb, void *);

/** Fake for @c lora_driver_api::cad. */
DECLARE_FAKE_VALUE_FUNC(int, lora_fake_cad,
			const struct device *, k_timeout_t);

/** Fake for @c lora_driver_api::cad_async. */
DECLARE_FAKE_VALUE_FUNC(int, lora_fake_cad_async,
			const struct device *, lora_cad_cb, void *);

/**
 * @brief Get the fake LoRa device.
 *
 * @return Pointer to the fake device, to pass wherever a LoRa device
 *         pointer is expected.
 */
const struct device *lora_fake_get_device(void);

/**
 * @brief Reset all fake call counters, arguments, return values, and staged data.
 *
 * Call this in your test fixture's before-each hook.
 */
void lora_fake_reset(void);

/* --------------------------------------------------------------------------
 * lora_recv helpers
 * -------------------------------------------------------------------------- */

/**
 * @brief Stage data for the next @c lora_recv() call.
 *
 * Automatically installs a custom_fake on @ref lora_fake_recv that copies
 * the staged data into the caller's buffer.
 *
 * @param data Payload bytes to stage.
 * @param len  Number of bytes in @p data.
 * @param rssi RSSI value to report.
 * @param snr  SNR value to report.
 */
void lora_fake_set_recv_data(const uint8_t *data, uint8_t len,
			     int16_t rssi, int8_t snr);

/**
 * @brief Simulate an asynchronous packet arrival.
 *
 * Invokes the callback registered via the last @c lora_recv_async() call,
 * delivering the data staged with @ref lora_fake_set_recv_data().
 */
void lora_fake_trigger_recv_async(void);

/* --------------------------------------------------------------------------
 * lora_send helpers
 * -------------------------------------------------------------------------- */

/**
 * @brief Retrieve a copy of the last buffer passed to @c lora_send().
 *
 * @param len_out  Output: number of bytes in the returned buffer.
 * @return Pointer to the copied data, valid until the next
 *         @ref lora_fake_reset() call, or NULL if @c lora_send() has not
 *         been called yet.
 */
const uint8_t *lora_fake_get_sent_data(uint32_t *len_out);
