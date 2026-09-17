#ifndef AKE_CRYPTO_H
#define AKE_CRYPTO_H

#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif

int ake_crypto_generate_keypair(const char *private_path, const char *public_path, char *error, size_t error_size);
int ake_crypto_sign_digest(const char *private_path, const unsigned char digest[32], unsigned char *signature, size_t signature_capacity, size_t *signature_size, char *error, size_t error_size);
int ake_crypto_verify_digest(const unsigned char *public_blob, size_t public_blob_size, const unsigned char digest[32], const unsigned char *signature, size_t signature_size, char *error, size_t error_size);
const char *ake_crypto_version(void);

#ifdef __cplusplus
}
#endif
#endif
