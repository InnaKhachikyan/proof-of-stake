#include <stdio.h>
#include <stdlib.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "chacha20.h"

bool chacha_session_inited = false;

const uint32_t CONSTANTS[4] = {
    0x61707865, // "expa"
    0x3320646e, // "nd 3"
    0x79622d32, // "2-by"
    0x6b206574  // "te k"
};

uint8_t key[32];
uint8_t nonce[12];
uint32_t key_word[8];
uint32_t nonce_word[3];
uint32_t counter = 1;

static inline uint32_t load_32uint(uint8_t *p) {
    return ((uint32_t)p[0])       |
           ((uint32_t)p[1] << 8)  |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

int key_gen(uint8_t *key_buffer, uint32_t *key_word, int size) {

	if (RAND_bytes(key_buffer, size) != 1) {
		fprintf(stderr, "CSPRNG key gen failed\n");
		return -1;
	}
	for(int i = 0; i < 8; i++) {
		key_word[i] = load_32uint(key_buffer + 4*i);
	}
	return 0;
}

int nonce_gen(uint8_t *nonce_buf, uint32_t *nonce_word, int size) {

	if(RAND_bytes(nonce_buf, size) != 1) {
		fprintf(stderr, "CSPRNG nonce gen failed\n");
		return -1;
	}
	for(int i = 0; i < 3; i++) {
		nonce_word[i] = load_32uint(nonce_buf + 4*i);
	}
	return 0;
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
    // Column rounds
    quarter_round(s, 0, 4,  8, 12);
    quarter_round(s, 1, 5,  9, 13);
    quarter_round(s, 2, 6, 10, 14);
    quarter_round(s, 3, 7, 11, 15);
}

static inline void odd_round(uint32_t *s) {
    // Diagonal rounds 
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

uint8_t* chacha20(uint8_t *stream, size_t nbits) {
    if (!chacha_session_inited) {
        if (key_gen(key, key_word, 32) != 0) return NULL;
        chacha_session_inited = true;
    }

    if (nonce_gen(nonce, nonce_word, 12) != 0) return NULL;
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

        for (int i = 0; i < 16; i++) {
            copy_arr[i] = arr[i];
        }
        for (int i = 0; i < 10; i++) {
            even_round(copy_arr);
            odd_round(copy_arr);
        }
        for (int i = 0; i < 16; i++) {
            copy_arr[i] += arr[i];
            final_value_uint32(block + 4*i, copy_arr[i]);
        }

        counter++;

        size_t chunk = nbytes - produced;
        if (chunk > 64) chunk = 64;
        memcpy(stream + produced, block, chunk);
        produced += chunk;
    }

    if (nbits & 7) {               
        uint8_t keep = (uint8_t)(nbits & 7);
        uint8_t mask = (uint8_t)((1u << keep) - 1u);
        stream[nbytes - 1] &= mask;
    }

    return stream;
}

int chacha20_generate(const uint8_t *key, const uint8_t *nonce, uint32_t *output, size_t count) {
    if (!key || !nonce || !output || count == 0) {
        fprintf(stderr, "Invalid parameters to chacha20_generate\n");
        return -1;
    }

    uint32_t key_words[8];
    for (int i = 0; i < 8; i++) {
        key_words[i] = load_32uint((uint8_t*)(key + 4*i));
    }

    uint32_t nonce_words[3];
    for (int i = 0; i < 3; i++) {
        nonce_words[i] = load_32uint((uint8_t*)(nonce + 4*i));
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

        for (int i = 0; i < 16; i++) {
            copy_arr[i] = arr[i];
        }
        for (int i = 0; i < 10; i++) {
            even_round(copy_arr);
            odd_round(copy_arr);
        }
        for (int i = 0; i < 16; i++) {
            copy_arr[i] += arr[i];
            final_value_uint32(block + 4*i, copy_arr[i]);
        }

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
