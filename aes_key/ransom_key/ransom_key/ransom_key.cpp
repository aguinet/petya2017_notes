// ransom_key.cpp : Defines the entry point for the console application.
//
#include "stdafx.h"

void dumpHex(const char* Name, uint8_t const* Data, size_t const Len)
{
	printf("%s:", Name);
	for (size_t i = 0; i < Len; ++i) {
		if ((i % 16 == 0)) {
			printf("\n");
		}
		printf("%02X ", Data[i]);

	}
	printf("\n====\n");
}

int main()
{
	HCRYPTPROV prov;

	if (!CryptAcquireContext(&prov,
		NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES,
		CRYPT_VERIFYCONTEXT)) {
		if (!CryptAcquireContext(&prov, 0, 0, 24, 0xF0000000)) {
			puts("error CryptAcquireContext");
			return 1;
		}
	}

	HCRYPTKEY rsaKey;
	if (!CryptGenKey(prov, CALG_RSA_KEYX, (2048U << 16) | CRYPT_EXPORTABLE, &rsaKey)) {
		puts("error CryptGenKey RSA");
		return 1;
	}

	HCRYPTKEY aesKey;
	if (!CryptGenKey(prov, CALG_AES_128, CRYPT_EXPORTABLE, &aesKey)) {
		puts("error cryptgenkey AES");
		return 1;
	}

	DWORD data = CRYPT_MODE_CBC;
	CryptSetKeyParam(aesKey, KP_MODE, (BYTE*)&data, 0);
	data = PKCS5_PADDING;
	CryptSetKeyParam(aesKey, KP_PADDING, (BYTE*)&data, 0);

	DWORD expKeyLen;
	if (!CryptExportKey(aesKey, rsaKey, SIMPLEBLOB, 0, 0, &expKeyLen)) {
		puts("error cryptexportkey len");
		return 1;
	}
	uint8_t* expKey = (uint8_t*)malloc(expKeyLen);
	if (!CryptExportKey(aesKey, rsaKey, SIMPLEBLOB, 0, expKey, &expKeyLen)) {
		puts("error cryptexporykey data");
		return 1;
	}
	dumpHex("encrypted_key", expKey, expKeyLen);
	
	FILE* f = fopen("encrypted_key", "wb");
	if (!f) {
		puts("unable to open encrypted_key for writing");
		return 1;
	}
	fwrite(expKey, 1, expKeyLen, f);
	fclose(f);

	uint8_t rsaKeyData[4096];
	DWORD rsaKeyLen = 4096;
	if (!CryptExportKey(rsaKey, 0, PRIVATEKEYBLOB, 0, rsaKeyData, &rsaKeyLen)) {
		puts("error cryptexportkey RSA");
		return 1;
	}
	f = fopen("rsa_key", "wb");
	if (!f) {
		puts("unable to open encrypted_key for writing");
		return 1;
	}
	fwrite(&rsaKeyData[0], 1, rsaKeyLen, f);
	fclose(f);

	printf("Print enter to call CryptDestroyKey and CryptReleaseContext\n");
	getchar();
	CryptDestroyKey(aesKey);
	CryptReleaseContext(prov, 0);
	printf("Done! Press enter to exit.\n");
	getchar();
    return 0;
}

