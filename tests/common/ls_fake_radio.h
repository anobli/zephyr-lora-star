/*
 * Copyright (c) 2026 Alexandre Bailon <abailon@baylibre.com>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file ls_fake_radio.h
 * @brief Test helpers on top of Zephyr's upstream FFF LoRa fake.
 *
 * The upstream fake (compatible "zephyr,fake-lora",
 * <zephyr/drivers/lora/lora_fake.h>) only provides bare FFF stubs, reset
 * automatically before every test by a ZTEST rule. This module adds what the
 * LoRa Star unit tests need on top of it:
 *  - capture of the last frame passed to lora_send(),
 *  - capture of the callback registered with lora_recv_async(), so a test can
 *    inject a received frame.
 *
 * The capture is done by installing custom_fake hooks, which the upstream
 * ZTEST rule removes before each test. Call ls_fake_radio_reset() from the
 * suite's before hook (suite hooks run after ZTEST rules) to install them.
 *
 * This file also provides DEFINE_FFF_GLOBALS for the test image.
 */

#pragma once

#include <stdint.h>
#include <zephyr/device.h>
#include <zephyr/drivers/lora.h>
#include <zephyr/drivers/lora/lora_fake.h>

/** @brief Get the fake LoRa device (first "zephyr,fake-lora" DT node). */
const struct device *ls_fake_radio_dev(void);

/**
 * @brief Install the capture hooks and clear all captured / staged state.
 *
 * Drops the sent-frame capture, the staged RX frame and the registered
 * lora_recv_async() callback. Does not reset the FFF call counters; the
 * upstream ZTEST rule does that before every test.
 */
void ls_fake_radio_reset(void);

/**
 * @brief Stage a frame to be delivered by ls_fake_radio_trigger_rx() or
 *        returned by the next lora_recv() call.
 */
void ls_fake_radio_set_rx(const uint8_t *data, uint8_t len, int16_t rssi, int8_t snr);

/**
 * @brief Deliver the staged frame to the callback registered with
 *        lora_recv_async(). No-op if RX is not armed.
 */
void ls_fake_radio_trigger_rx(void);

/**
 * @brief Get a copy of the last buffer passed to lora_send().
 *
 * @param len_out Output: number of bytes in the returned buffer.
 * @return Pointer to the copy, or NULL if nothing was sent since the last
 *         ls_fake_radio_reset().
 */
const uint8_t *ls_fake_radio_get_tx(uint32_t *len_out);
