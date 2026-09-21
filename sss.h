#ifndef SSS_H

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

#endif