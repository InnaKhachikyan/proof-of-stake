#ifndef CHACHA20_H
#define CHACHA20_H

#include <stdint.h>
#include <stddef.h>

int chacha20_generate(const uint8_t *key, const uint8_t *nonce, uint32_t *output, size_t count);

#endif
