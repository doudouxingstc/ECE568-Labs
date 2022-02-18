#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"


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


int
main(int argc, char * argv[])
{
	if ( argc != 4 ) {
		printf("Usage: %s [issuer] [accountName] [secretHex]\n", argv[0]);
		return(-1);
	}

	char *	issuer = argv[1];
	char *	accountName = argv[2];
	char *	secret_hex = argv[3];

	assert (strlen(secret_hex) <= 20);

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator
	char secret_hex_encoded[17];
	uint8_t temp[10];
	char URL[512];

	for (int i = 0; i < 10; i++) {
		temp[i] = char_to_int(secret_hex[2 * i]) * 16 + char_to_int(secret_hex[2 * i + 1]);
	}

	assert(base32_encode(temp, 10, secret_hex_encoded, 16) != -1);
	
	secret_hex_encoded[16] = '\0';

	sprintf(URL, 
		"otpauth://totp/%s?issuer=%s&secret=%s&period=30", 
		urlEncode(accountName), 
		urlEncode(issuer), 
		secret_hex_encoded);

	displayQRcode(URL);

	return (0);
}
