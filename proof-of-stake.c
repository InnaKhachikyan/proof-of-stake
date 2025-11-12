#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "chacha20.h"

int main(int argc, char **argv) {
	if (argc < 3) {
        	fprintf(stderr, "Usage: %s <key_hex_64chars> <nonce_hex_24chars>\n", argv[0]);
        	return 1;
	}

	const char *key_hex = argv[1];
	const char *nonce_hex = argv[2];

	if (strlen(key_hex) != 64 || strlen(nonce_hex) != 24) {
        	fprintf(stderr, "Error: key must be 64 hex chars (32 bytes) and nonce 24 hex chars (12 bytes)\n");
        	return 1;
	}

	uint8_t key_in[32];
	uint8_t nonce_in[12];
	for (int i = 0; i < 32; ++i) {
		sscanf(&key_hex[i * 2], "%2hhx", &key_in[i]);
	}
	for (int i = 0; i < 12; ++i) {
		sscanf(&nonce_hex[i * 2], "%2hhx", &nonce_in[i]);
	}

	uint32_t rand_nums[320];
	if (chacha20_unique_mod_0_999(key_in, nonce_in, rand_nums) != 0) {
		fprintf(stderr, "unique sampling failed\n");
        	return 1;
	}

	for (size_t i = 0; i < 320; i++) {
		if (i % 20 == 0) printf("\n");
        	printf("%3u ", rand_nums[i]);
	}
	printf("\n");
	return 0;
}


