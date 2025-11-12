#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "chacha20.h"

bool chacha_session_inited = false;

const uint32_t CONSTANTS[4] = {
    0x61707865,
    0x3320646e,
    0x79622d32,
    0x6b206574
};

uint8_t key[32];
uint8_t nonce[12];
uint32_t key_word[8];
uint32_t nonce_word[3];
uint32_t counter = 1;

static inline uint32_t load_32uint(const uint8_t *p) {
    return ((uint32_t)p[0])       |
           ((uint32_t)p[1] << 8)  |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

void build_init_array(const uint32_t *constants, uint32_t *keys, uint32_t *counter, uint32_t *nonce, uint32_t *arr) {
    for(int i = 0; i < 4; i++) {
        arr[i] = constants[i];
        arr[i + 4] = keys[i];
        arr[i + 2*4] = keys[i + 4];
        if(i == 0) {
            arr[i + 3*4] = *counter;
        }
        else {
            arr[i + 3*4] = nonce[i-1];
        }
    }
}

static inline uint32_t rotl(uint32_t s, int n) {
    return (s << n) | (s >> (32 - n));
}

static inline void quarter_round(uint32_t *s, int a, int b, int c, int d) {
    s[a] += s[b];  s[d] ^= s[a];  s[d] = rotl(s[d], 16);
    s[c] += s[d];  s[b] ^= s[c];  s[b] = rotl(s[b], 12);
    s[a] += s[b];  s[d] ^= s[a];  s[d] = rotl(s[d],  8);
    s[c] += s[d];  s[b] ^= s[c];  s[b] = rotl(s[b],  7);
}

static inline void even_round(uint32_t *s) {
    quarter_round(s, 0, 4,  8, 12);
    quarter_round(s, 1, 5,  9, 13);
    quarter_round(s, 2, 6, 10, 14);
    quarter_round(s, 3, 7, 11, 15);
}

static inline void odd_round(uint32_t *s) {
    quarter_round(s, 0, 5, 10, 15);
    quarter_round(s, 1, 6, 11, 12);
    quarter_round(s, 2, 7,  8, 13);
    quarter_round(s, 3, 4,  9, 14);
}

static inline void final_value_uint32(uint8_t *result, uint32_t current) {
    result[0] = (uint8_t)(current);
    result[1] = (uint8_t)(current >> 8);
    result[2] = (uint8_t)(current >> 16);
    result[3] = (uint8_t)(current >> 24);
}

uint8_t* chacha20(uint8_t *stream, size_t nbits, const uint8_t *key_in, const uint8_t *nonce_in) {
    for (int i = 0; i < 8; i++) key_word[i] = load_32uint(key_in + 4*i);
    for (int i = 0; i < 3; i++) nonce_word[i] = load_32uint(nonce_in + 4*i);
    counter = 1;

    size_t nbytes = (nbits + 7) / 8;
    size_t produced = 0;

    while (produced < nbytes) {
        if (counter == 0) {
            fprintf(stderr, "Counter overflow - too much data requested\n");
            return NULL;
        }

        uint32_t arr[16];
        uint32_t copy_arr[16];
        uint8_t block[64];

        build_init_array((uint32_t*)CONSTANTS, key_word, &counter, nonce_word, arr);

        for (int i = 0; i < 16; i++) copy_arr[i] = arr[i];
        for (int i = 0; i < 10; i++) { even_round(copy_arr); odd_round(copy_arr); }
        for (int i = 0; i < 16; i++) { copy_arr[i] += arr[i]; final_value_uint32(block + 4*i, copy_arr[i]); }

        counter++;

        size_t chunk = nbytes - produced;
        if (chunk > 64) chunk = 64;
        memcpy(stream + produced, block, chunk);
        produced += chunk;
    }

    if (nbits & 7) {
        uint8_t keep = (uint8_t)(nbits & 7);
        stream[nbytes - 1] &= (uint8_t)(0xFF << (8 - keep));
    }

    return stream;
}

int chacha20_generate(const uint8_t *key, const uint8_t *nonce, uint32_t *output, size_t count) {
    if (!key || !nonce || !output || count== 0) {
        fprintf(stderr, "Invalid parameters to chacha20_generate\n");
        return -1;
    }

    uint32_t key_words[8];
    for (int i = 0; i < 8; i++) {
        key_words[i] = load_32uint(key + 4*i);
    }

    uint32_t nonce_words[3];
    for (int i = 0; i < 3; i++) {
        nonce_words[i] = load_32uint(nonce + 4*i);
    }

    size_t nbytes = count * sizeof(uint32_t);
    uint8_t *stream = (uint8_t*)malloc(nbytes);
    if (!stream) {
        fprintf(stderr, "Memory allocation failed\n");
        return -1;
    }

    uint32_t counter = 1;
    size_t produced = 0;

    while (produced < nbytes) {
        if (counter == 0) {
            fprintf(stderr, "Counter overflow - too much data requested\n");
            free(stream);
            return -1;
        }

        uint32_t arr[16];
        uint32_t copy_arr[16];
        uint8_t block[64];

        build_init_array((uint32_t*)CONSTANTS, key_words, &counter, nonce_words, arr);

        for (int i = 0; i < 16; i++) copy_arr[i] = arr[i];
        for (int i = 0; i < 10; i++) { even_round(copy_arr); odd_round(copy_arr); }
        for (int i = 0; i < 16; i++) { copy_arr[i] += arr[i]; final_value_uint32(block + 4*i, copy_arr[i]); }

        counter++;

        size_t chunk = nbytes - produced;
        if (chunk > 64) chunk = 64;
        memcpy(stream + produced, block, chunk);
        produced += chunk;
    }

    for (size_t i = 0; i < count; i++) {
        output[i] = load_32uint(stream + 4*i);
    }

    free(stream);
    return 0;
}

static int next_u32_pool(const uint8_t *key_in, const uint8_t *nonce_in,
                         uint32_t *pool, size_t pool_cap,
                         size_t *idx, size_t *have,
                         uint8_t nonce_work[12], uint32_t *nonce_suffix)
{
    if (*idx >= *have) {
        memcpy(nonce_work, nonce_in, 12);
        uint32_t s = *nonce_suffix;
        nonce_work[8]  ^= (uint8_t)(s);
        nonce_work[9]  ^= (uint8_t)(s >> 8);
        nonce_work[10] ^= (uint8_t)(s >> 16);
        nonce_work[11] ^= (uint8_t)(s >> 24);
        *nonce_suffix = *nonce_suffix + 1;
        if (chacha20_generate(key_in, nonce_work, pool, pool_cap) != 0) return -1;
        *idx = 0;
        *have = pool_cap;
    }
    return 0;
}

static int uniform_u32_mod_1000_from_pool(const uint8_t *key_in, const uint8_t *nonce_in,
                                          uint32_t *pool, size_t pool_cap,
                                          size_t *idx, size_t *have,
                                          uint8_t nonce_work[12], uint32_t *nonce_suffix,
                                          uint32_t *out_v)
{
    const uint32_t m = 1000u;
    const uint32_t limit = 0xFFFFFFFFu - (0xFFFFFFFFu % m);
    for (;;) {
        if (*idx >= *have) {
            if (next_u32_pool(key_in, nonce_in, pool, pool_cap, idx, have, nonce_work, nonce_suffix) != 0) return -1;
        }
        uint32_t r = pool[(*idx)++];
        if (r <= limit) {
            *out_v = r % m;
            return 0;
        }
    }
}

int chacha20_unique_mod_0_999(const uint8_t *key_in, const uint8_t *nonce_in, uint32_t rand_nums[320]) {
    uint8_t seen[1000];
    memset(seen, 0, sizeof(seen));
    uint32_t pool[2048];
    size_t idx = 0, have = 0;
    uint8_t nonce_work[12];
    uint32_t nonce_suffix = 0;
    size_t k = 0;
    while (k < 320) {
        uint32_t v;
        if (uniform_u32_mod_1000_from_pool(key_in, nonce_in, pool, 2048, &idx, &have, nonce_work, &nonce_suffix, &v) != 0) {
            return -1;
        }
        if (!seen[v]) {
            seen[v] = 1;
            rand_nums[k++] = v;
        }
    }
    return 0;
}

