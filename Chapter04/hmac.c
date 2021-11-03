#include <openssl/core_names.h>
#include <openssl/evp.h>

#include <assert.h>
#include <stdio.h>

const size_t HMAC_LENGTH = 256 / 8;

int calculate_hmac(FILE* in_file, const unsigned char* key, size_t key_length, unsigned char* hmac, FILE* error_stream);

int main(int argc, char** argv) {
    int exit_code = 0;

    FILE* in_file = NULL;
    unsigned char* key = NULL;
    unsigned char hmac[HMAC_LENGTH];

    if (argc != 3) {
        fprintf(stderr, "Usage: %s INPUT_FILE KEY_HEX\n", argv[0]);
        exit_code = 1;
        goto cleanup;
    }

    const char* in_fname  = argv[1];
    const char* key_hex   = argv[2];

    long key_length = 0;
    key = OPENSSL_hexstr2buf(key_hex, &key_length);
    if (!key || key_length <= 0) {
        fprintf(stderr, "Wrong key \"%s\", must consist of even number of hex digits\n", key_hex);
        goto failure;
    }

    in_file = fopen(in_fname, "rb");
    if (!in_file) {
        fprintf(stderr, "Could not open input file \"%s\"\n", in_fname);
        goto failure;
    }

    int err = calculate_hmac(in_file, key, key_length, hmac, stderr);
    if (err) {
        fprintf(stderr, "HMAC calculation failed\n");
        goto failure;
    }

    for (size_t i = 0; i < HMAC_LENGTH; ++i) {
        printf("%02X", hmac[i]);
    }
    printf("\n");

    goto cleanup;

failure:
    exit_code = 1;
cleanup:
    OPENSSL_free(key);
    if (in_file)
        fclose(in_file);

    return exit_code;
}

int calculate_hmac(FILE* in_file, const unsigned char* key, size_t key_length, unsigned char* hmac, FILE* error_stream) {
    int exit_code = 0;

    EVP_MAC* mac = NULL;
    EVP_MAC_CTX* ctx = NULL;

    const size_t BUF_SIZE = 64 * 1024;
    unsigned char* in_buf = malloc(BUF_SIZE);

    mac = EVP_MAC_fetch(NULL, OSSL_MAC_NAME_HMAC, NULL);

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(
            OSSL_MAC_PARAM_DIGEST, OSSL_DIGEST_NAME_SHA3_256, 0),
        OSSL_PARAM_construct_end()
    };

    ctx = EVP_MAC_CTX_new(mac);
    int ok = EVP_MAC_init(ctx, key, key_length, params);

    while (!feof(in_file)) {
        size_t in_nbytes = fread(in_buf, 1, BUF_SIZE, in_file);
        ok = EVP_MAC_update(ctx, in_buf, in_nbytes);
    }

    size_t out_nbytes = 0;
    ok = EVP_MAC_final(ctx, hmac, &out_nbytes, HMAC_LENGTH);

    if (ferror(in_file)) {
        if (error_stream)
            fprintf(error_stream, "I/O error\n");
        goto failure;
    }

    if (!ok) {
        if (error_stream)
            fprintf(error_stream, "EVP API error\n");
        goto failure;
    }

    goto cleanup;

failure:
    exit_code = 1;
cleanup:
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    free(in_buf);

    return exit_code;
}
