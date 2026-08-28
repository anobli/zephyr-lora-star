/*
 * Copyright (c) 2026 Alexandre Bailon <abailon@baylibre.com>
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file radio.h
 * @brief LoRa Star radio transport API.
 *
 * Thin wrapper around the Zephyr LoRa driver API, applying the fixed LoRa
 * Star modem configuration (frequency, SF7, BW125, CR4/5) on every TX/RX
 * switch.
 */

#ifndef LORA_STAR_RADIO_H
#define LORA_STAR_RADIO_H

#include <stdint.h>
#include <stddef.h>
#include <zephyr/device.h>
#include <zephyr/drivers/lora.h>

/**
 * @brief Initialise the radio for transmission.
 *
 * Applies the fixed LoRa Star modem configuration in TX mode.
 *
 * @param lora_dev  LoRa radio device.
 * @return 0 on success, negative errno on failure.
 */
int ls_radio_init(const struct device *lora_dev);

/**
 * @brief Transmit a buffer over the radio.
 *
 * Reconfigures the radio for TX, then blocks until the transmission
 * completes.
 *
 * @param lora_dev  LoRa radio device.
 * @param data      Buffer to transmit.
 * @param len       Number of bytes to transmit.
 * @return 0 on success, negative errno on failure.
 */
int ls_radio_tx(const struct device *lora_dev, uint8_t *data, size_t len);

/**
 * @brief Start asynchronous reception.
 *
 * Reconfigures the radio for RX, then arms asynchronous reception; @p rx_cb
 * is invoked by the Zephyr LoRa driver for every received frame.
 *
 * @param lora_dev   LoRa radio device.
 * @param rx_cb      Callback invoked on frame reception.
 * @param user_data  Opaque pointer forwarded to @p rx_cb.
 * @return 0 on success, -EINVAL if @p rx_cb is NULL, negative errno on
 *         other failures.
 */
int ls_radio_rx_start(const struct device *lora_dev, lora_recv_cb rx_cb, void *user_data);

/**
 * @brief Stop asynchronous reception.
 *
 * Safe to call when RX is not running.
 *
 * @param lora_dev  LoRa radio device.
 * @return 0 on success, negative errno on failure.
 */
int ls_radio_rx_stop(const struct device *lora_dev);

/**
 * @brief Compute the on-air time for a frame of the given length.
 *
 * Uses the fixed modem configuration (SF7, BW125, CR4/5, preamble=8).
 *
 * @param lora_dev  LoRa radio device.
 * @param frame_len Total frame length in bytes as passed to the radio.
 * @return Time on air in milliseconds, rounded up.
 */
uint32_t ls_radio_airtime_ms(const struct device *lora_dev, size_t frame_len);

#endif /* LORA_STAR_RADIO_H */
