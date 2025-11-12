#include <stdio.h>
#include <stdlib.h>
#include <openssl/rand.h>
#include <openssl/rand_drbg.h>
#include <string.h>
#include <stdint.h>

void generate_random_integers(const unsigned char *seed, size_t seed_len, uint32_t nums[320]) {
    RAND_DRBG *drbg = RAND_DRBG_new(NID_aes_256_ctr, 0, NULL);
    if (!drbg) {
        fprintf(stderr, "Failed to create DRBG\n");
        return;
    }

    if (RAND_DRBG_instantiate(drbg, seed, seed_len) != 1) {
        fprintf(stderr, "Failed to instantiate DRBG\n");
        RAND_DRBG_free(drbg);
        return;
    }

    if (RAND_DRBG_generate(drbg, (unsigned char*)nums, sizeof(nums), 0, NULL, 0) != 1) {
        fprintf(stderr, "Failed to generate random bytes\n");
        RAND_DRBG_uninstantiate(drbg);
        RAND_DRBG_free(drbg);
        return;
    }

    for (int i = 0; i < 320; i++)
        printf("%u\n", nums[i]);

    RAND_DRBG_uninstantiate(drbg);
    RAND_DRBG_free(drbg);
}

int main(void) {
	if (argc < 2) {
        	fprintf(stderr, "Usage: %s <seed_string>\n", argv[0]);
        	return 1;
    	}

	const unsigned char *seed = (const unsigned char*)argv[1];
	size_t seed_len = strlen(argv[1]);
	uint32_t rand_nums[320];

	generate_random_integers(seed, seed_len, rand_nums);

	return 0;
}

