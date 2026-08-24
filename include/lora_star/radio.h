#include <stdint.h>
#include <stddef.h>
#include <zephyr/device.h>
#include <zephyr/drivers/lora.h>

int ls_radio_init(const struct device *lora_dev);
int ls_radio_tx(const struct device *lora_dev, uint8_t *data, size_t len);
int ls_radio_rx_start(const struct device *lora_dev, lora_recv_cb rx_cb, void *user_data);
int ls_radio_rx_stop(const struct device *lora_dev);

/**
 * @brief Compute the on-air time for a frame of the given length.
 *
 * Uses the fixed modem configuration (SF7, BW125, CR4/5, preamble=8).
 *
 * @param frame_len Total frame length in bytes as passed to the radio.
 * @return Time on air in milliseconds, rounded up.
 */
uint32_t ls_radio_airtime_ms(const struct device *lora_dev, size_t frame_len);
