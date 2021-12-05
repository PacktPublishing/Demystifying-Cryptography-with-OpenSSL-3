#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

#include <stdio.h>
#include <string.h>

const size_t KEY_LENGTH = 256 / 8;

int derive_key(const char* password, const unsigned char* salt, size_t salt_length, unsigned char* key, FILE* error_stream);

int main(int argc, char** argv) {
    int exit_code = 0;

    unsigned char* salt = NULL;
    unsigned char key[KEY_LENGTH];

    if (argc != 3) {
        fprintf(stderr, "Usage: %s PASSWORD SALT_HEX\n", argv[0]);
        exit_code = 1;
        goto cleanup;
    }

    const char* password  = argv[1];
    const char* salt_hex  = argv[2];

    long salt_length = 0;
    salt = OPENSSL_hexstr2buf(salt_hex, &salt_length);
    if (!salt || salt_length <= 0) {
        fprintf(stderr, "Wrong salt \"%s\", must consist of even number of hex digits\n", salt_hex);
        goto failure;
    }

    int err = derive_key(password, salt, salt_length, key, stderr);
    if (err) {
        fprintf(stderr, "Key derivation failed\n");
        goto failure;
    }

    for (size_t i = 0; i < KEY_LENGTH; ++i) {
        if (i != 0)
            printf(":");
        printf("%02X", key[i]);
    }
    printf("\n");

    goto cleanup;

failure:
    exit_code = 1;
cleanup:
    OPENSSL_free(salt);

    return exit_code;
}

int derive_key(const char* password, const unsigned char* salt, size_t salt_length, unsigned char* key, FILE* error_stream) {
    int exit_code = 0;

    EVP_KDF* kdf = NULL;
    EVP_KDF_CTX* ctx = NULL;

    kdf = EVP_KDF_fetch(NULL, OSSL_KDF_NAME_SCRYPT, NULL);

    // OWASP recommended settings.
    uint64_t scrypt_n = 65536;
    uint32_t scrypt_r = 8;
    uint32_t scrypt_p = 1;

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_PASSWORD, (char*)password, strlen(password)),
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_SALT, (char*)salt, salt_length),
        OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_SCRYPT_N, &scrypt_n),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_SCRYPT_R, &scrypt_r),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_SCRYPT_P, &scrypt_p),
        OSSL_PARAM_construct_end()
    };

    ctx = EVP_KDF_CTX_new(kdf);
    int ok = EVP_KDF_derive(ctx, key, KEY_LENGTH, params);

    if (!ok) {
        if (error_stream)
            fprintf(error_stream, "EVP API error\n");
        goto failure;
    }

    goto cleanup;

failure:
    exit_code = 1;
cleanup:
    EVP_KDF_CTX_free(ctx);
    EVP_KDF_free(kdf);

    return exit_code;
}
