#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "lib/sha1.h"
#include <time.h>
#include <stdlib.h>


int 
char_to_int(char c) 
{
	if (c >= 65 && c <= 70) {
		return c - 55;
	} else if (c >= 48 && c <= 57) {
		return c - 48;
	} else {
		return 0;
	}
}


static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	uint8_t secret_key[64];
	uint8_t key_ipad[64];
	uint8_t key_opad[64];

	memset(secret_key, 0, 64);
	memset(key_ipad, 0x00, 64);
	memset(key_opad, 0x00, 64);

	for (int i = 0; i < 10; i++) {
		secret_key[i] = char_to_int(secret_hex[2 * i]) * 16 + char_to_int(secret_hex[2 * i + 1]);
	}

	for (int i = 0; i < 64; i++) {
		key_ipad[i] = secret_key[i] ^ 0x36;
		key_opad[i] = secret_key[i] ^ 0x5c;
	}

	uint64_t period = time(NULL) / 30;
	uint8_t msg[8];

	for (int i = 7; i >= 0; i--) {
		msg[i] = 0x00ff & (period >> (8 * (7 - i))); // ?
	}

	// HMAC
	SHA1_INFO ctx;
	uint8_t sha_in[SHA1_DIGEST_LENGTH];
	sha1_init(&ctx);
	sha1_update(&ctx, key_ipad, 64);
	sha1_update(&ctx, msg, 8);
	sha1_final(&ctx, sha_in);

	uint8_t sha_out[SHA1_DIGEST_LENGTH];
	sha1_init(&ctx);
	sha1_update(&ctx, key_opad, 64);
	sha1_update(&ctx, sha_in, 20);
	sha1_final(&ctx, sha_out);

	int offset = sha_out[19] & 0xf;
	int bin = (sha_out[offset] & 0x7f)     << 24
			| (sha_out[offset + 1] & 0xff) << 16
			| (sha_out[offset + 2] & 0xff) << 8
			| (sha_out[offset + 3] & 0xff);

	int val = bin % 1000000;
	int TOTP_val = atoi(TOTP_string);

	return val == TOTP_val;
}


int
main(int argc, char * argv[])
{
	if ( argc != 3 ) {
		printf("Usage: %s [secretHex] [TOTP]\n", argv[0]);
		return(-1);
	}

	char *	secret_hex = argv[1];
	char *	TOTP_value = argv[2];

	assert (strlen(secret_hex) <= 20);
	assert (strlen(TOTP_value) == 6);

	printf("\nSecret (Hex): %s\nTOTP Value: %s (%s)\n\n",
		secret_hex,
		TOTP_value,
		validateTOTP(secret_hex, TOTP_value) ? "valid" : "invalid");

	return(0);
}
