#ifndef LORA_STAR_LS_CRYPTO_H
#define LORA_STAR_LS_CRYPTO_H

#include <stdint.h>
#include <lora_star/ls_frame.h>

/*
 * Generate an ephemeral Curve25519 key pair.
 * priv and pub are each 32 bytes.
 */
int ls_crypto_ecdh_gen_keypair(uint8_t pub[LS_PUBKEY_SIZE],
			       uint8_t priv[LS_PUBKEY_SIZE]);

/*
 * Compute the Curve25519 ECDH shared secret.
 * shared[] receives 32 bytes.
 */
int ls_crypto_ecdh_shared(const uint8_t priv[LS_PUBKEY_SIZE],
			   const uint8_t peer_pub[LS_PUBKEY_SIZE],
			   uint8_t shared[LS_PUBKEY_SIZE]);

/*
 * Derive the 16-byte session key via HKDF-SHA256.
 *   ikm  = shared (32 B)
 *   salt = dev_eui (8 B) || nonce (4 B)
 *   info = "lora_star_v1"
 */
int ls_crypto_derive_session_key(const uint8_t shared[LS_PUBKEY_SIZE],
				 const uint8_t dev_eui[LS_DEV_EUI_SIZE],
				 const uint8_t nonce[LS_NONCE_SIZE],
				 uint8_t session_key[LS_SESSION_KEY_SIZE]);

/*
 * Encrypt/decrypt the short address in JOIN_ACCEPT.
 * key = shared[0..15], nonce used as AES-CTR counter seed.
 */
int ls_crypto_encrypt_short_addr(const uint8_t shared[LS_PUBKEY_SIZE],
				 const uint8_t nonce[LS_NONCE_SIZE],
				 uint16_t plain, uint16_t *cipher_out);

int ls_crypto_decrypt_short_addr(const uint8_t shared[LS_PUBKEY_SIZE],
				 const uint8_t nonce[LS_NONCE_SIZE],
				 uint16_t cipher, uint16_t *plain_out);

/*
 * AES-128-CTR encrypt or decrypt a frame payload (symmetric).
 * nonce block = FCNT(4B LE) || SRC(2B LE) || 0x00...(10B)
 */
int ls_crypto_payload_crypt(const uint8_t session_key[LS_SESSION_KEY_SIZE],
			    uint32_t fcnt, uint16_t src,
			    const uint8_t *in, uint8_t *out, uint8_t len);

/*
 * Compute the 4-byte AES-CMAC MIC over the frame header + (encrypted) payload.
 * For JOIN_REQ: key = DevEUI zero-padded to 16 bytes.
 */
int ls_crypto_compute_mic(const uint8_t key[LS_SESSION_KEY_SIZE],
			  const uint8_t *header, uint8_t header_len,
			  const uint8_t *payload, uint8_t payload_len,
			  uint8_t mic[LS_MIC_SIZE]);

/*
 * Build the 16-byte JOIN_REQ integrity key: DevEUI || 0x00…(8B).
 */
void ls_crypto_join_req_key(const uint8_t dev_eui[LS_DEV_EUI_SIZE],
			    uint8_t key[LS_SESSION_KEY_SIZE]);

#endif /* LORA_STAR_LS_CRYPTO_H */
