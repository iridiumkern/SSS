#ifndef SSS_H

#include <stdbool.h>
#include <stddef.h>

#define HASH_OUT_SIZE 64

/**
 * @brief SHA512 hash
 * 
 * @param input Input to hash
 * @param input_size The size of the input
 * @param output The hash (64 bytes)
 * @return true The hash worked
 * @return false The hash value was not computed
 */
bool sss_sha512(const void *input, size_t input_size, void *output);

/**
 * @brief Provides 512bits (64 bytes) of cryptographically secure random numbers
 * 
 * @param output The output, 64 byte buffer
 * @return true The output is safe to use and should be considered cryptographically secure
 * @return false The output is unsafe and should not be used, retry or fail
 */
bool sss_get512randsecure(void *output);

bool sss_generate_keypair(unsigned char *master_seed, unsigned char *root);
bool sss_sign(const unsigned char *master_seed, const void *message, size_t message_size, unsigned char *signature_out);
bool sss_verify(const unsigned char *root, const void *message, size_t message_size, const unsigned char *signature_in);

#ifndef SSS_DEBUG
// Only use this when actually debugging, uses printf!
void sss_debug_test(void);
#endif

#endif