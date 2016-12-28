#include <mbedtls/ecdh.h>
#include <mbedtls/pk.h>
#include <mbedtls/gcm.h>
#include <mbedtls/aes.h>
#include <mbedtls/sha256.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>

/*
	gcc -Wall -o dh dh.c -lmbedtls -lmbedcrypto
	./dh < foo 
	dh_shared : XX
	sha256 out: YY
	...
	{"expiry":14772423230,"token":"ABCD"}
	<moar hex>
	{"priority":0,"psk":"test123","keyMgmt":"WPA_PSK","ssid":"Cyber"}
*/

static void hexdump(const uint8_t *d, size_t n) {
	for(;n;n--,d++)
		printf("%02x ",*d);
	puts("");
}

static uint8_t binbuf[512];

static uint8_t *hexparse(char *buf, size_t *len) {
	uint8_t *ptr;
	for(ptr=binbuf;*buf >= 0x20;buf+=3,ptr++)
		*ptr = strtoul(buf, NULL, 16);
	if(len)
		*len = ptr - binbuf;
	return binbuf;
}

static void asciidump(const uint8_t *d, size_t len) {
	for(;len;len--,d++) {
		uint8_t v = *d >= 0x20 ? *d : '.';
		v = v <= 0x7e ? v : '.';
		putchar(v);
	}
	puts("");
}

int main(int argc, char **argv) {
	mbedtls_pk_context peer_pk, mykey;
	mbedtls_ecdh_context ecdh;
	mbedtls_gcm_context gcm;
	char line[1024];
	uint8_t output[1024];
	uint8_t dh_obuf[32], hash_obuf[32];
	size_t dh_olen = sizeof(dh_obuf);
	int res;
	
	mbedtls_pk_init(&peer_pk);
	mbedtls_pk_init(&mykey);
	mbedtls_ecdh_init(&ecdh);
	mbedtls_gcm_init(&gcm);
	
	res = mbedtls_pk_parse_keyfile(&mykey, "prime256v1-key.pem", NULL);
	assert(!res);
	
	res = mbedtls_ecdh_get_params(&ecdh, mbedtls_pk_ec(mykey), MBEDTLS_ECDH_OURS);
	assert(!res);
	
	res = mbedtls_pk_parse_public_keyfile(&peer_pk, "peer_pubkey.pem");
	assert(!res);
	
	res = mbedtls_ecdh_get_params(&ecdh, mbedtls_pk_ec(peer_pk), MBEDTLS_ECDH_THEIRS);
	assert(!res);
	
	res = mbedtls_ecdh_calc_secret(&ecdh, &dh_olen, dh_obuf, sizeof(dh_obuf), NULL, NULL);
	assert(!res);
	
	printf("dh_shared : ");
	hexdump(dh_obuf, dh_olen);
	
	mbedtls_sha256(dh_obuf, dh_olen, hash_obuf, 0);
	
	printf("sha256 out: ");
	hexdump(hash_obuf, 32);
	
	res = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, hash_obuf, 128);
	assert(!res);
	
	while(fgets(line, sizeof(line), stdin)) {
		size_t blen, add_len = 0, tag_len = 16;
		uint8_t *iv, *bin = hexparse(line, &blen), *add = NULL, *tag = NULL;
		if(blen <= (3*3 + 32))
			break;
		iv = bin+3;
		tag = bin+3+16+3;
		bin = bin+3+16+3+16+3;
		blen -= 3+16+3+16+3;
		res = mbedtls_gcm_auth_decrypt(&gcm, blen, iv, 16, add, add_len, tag, tag_len, bin, output);
		assert(!res);
		hexdump(output,blen);
		asciidump(output,blen);
	}
	
	return 0;
}
