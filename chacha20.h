#ifndef CHACHA20_H
#define CHACHA20_H

#include <stdint.h>
#include <stddef.h>

int chacha20_unique_mod_0_999(const uint8_t *key_in, const uint8_t *nonce_in, uint32_t rand_nums[320]);

#endif
