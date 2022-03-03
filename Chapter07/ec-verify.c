#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/pem.h>

#include <stdio.h>
#include <string.h>

int verify(FILE* in_file, FILE* sig_file, FILE* pkey_file, FILE* error_stream);

int main(int argc, char** argv) {
    int exit_code = 0;

    FILE* in_file   = NULL;
    FILE* sig_file  = NULL;
    FILE* pkey_file = NULL;

    if (argc != 4) {
        fprintf(stderr, "Usage: %s INPUT_FILE OUTPUT_FILE PUBLIC_KEY_FILE\n", argv[0]);
        exit_code = 1;
        goto cleanup;
    }

    const char* in_fname   = argv[1];
    const char* sig_fname  = argv[2];
    const char* pkey_fname = argv[3];

    in_file = fopen(in_fname, "rb");
    if (!in_file) {
        fprintf(stderr, "Could not open input file \"%s\"\n", in_fname);
        goto failure;
    }

    sig_file = fopen(sig_fname, "rb");
    if (!sig_file) {
        fprintf(stderr, "Could not open signature file \"%s\"\n", sig_fname);
        goto failure;
    }

    pkey_file = fopen(pkey_fname, "rb");
    if (!pkey_file) {
        fprintf(stderr, "Could not open public key file \"%s\"\n", pkey_fname);
        goto failure;
    }

    int err = verify(in_file, sig_file, pkey_file, stderr);
    if (err) {
        fprintf(stderr, "Verification failed\n");
        goto failure;
    }

    fprintf(stderr, "Verification succeeded\n");
    goto cleanup;

failure:
    exit_code = 1;
cleanup:
    if (pkey_file)
        fclose(pkey_file);
    if (sig_file)
        fclose(sig_file);
    if (in_file)
        fclose(in_file);

    return exit_code;
}

int verify(FILE* in_file, FILE* sig_file, FILE* pkey_file, FILE* error_stream) {
    int exit_code = 0;
    int err = 1;

    const size_t BUF_SIZE = 64 * 1024;

    EVP_PKEY* pkey = NULL;
    EVP_MD_CTX* md_ctx = NULL;

    unsigned char* in_buf  = NULL;
    unsigned char* sig_buf = NULL;

    ERR_clear_error();

    fseek(sig_file, 0, SEEK_END);
    long sig_file_len = ftell(sig_file);
    fseek(sig_file, 0, SEEK_SET);

    sig_buf = malloc(sig_file_len);
    size_t sig_len = fread(sig_buf, 1, sig_file_len, sig_file);
    if (sig_file_len <= 0 || sig_len != sig_file_len) {
        if (error_stream)
            fprintf(error_stream, "Could not load signature\n");
        goto failure;
    }

    pkey = PEM_read_PUBKEY(pkey_file, NULL, NULL, NULL);
    if (!pkey) {
        if (error_stream)
            fprintf(error_stream, "Could not load public key\n");
        goto failure;
    }

    md_ctx = EVP_MD_CTX_new();
    err = EVP_DigestVerifyInit_ex(
        md_ctx,
        NULL,
        OSSL_DIGEST_NAME_SHA3_512,
        NULL,
        NULL,
        pkey,
        NULL);

    in_buf = malloc(BUF_SIZE);
    while (!feof(in_file)) {
        size_t in_nbytes = fread(in_buf, 1, BUF_SIZE, in_file);
        err = EVP_DigestVerifyUpdate(md_ctx, in_buf, in_nbytes);
    }

    err = EVP_DigestVerifyFinal(md_ctx, sig_buf, sig_len);

    if (ferror(in_file) || ferror(sig_file) || ferror(pkey_file)) {
        if (error_stream)
            fprintf(error_stream, "I/O error\n");
        goto failure;
    }

    if (err != 1) {
        if (error_stream)
            fprintf(error_stream, "EVP_API error\n");
        goto failure;
    }

    goto cleanup;

failure:
    exit_code = 1;
cleanup:
    free(in_buf);
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    free(sig_buf);

    if (ERR_peek_error()) {
        exit_code = 1;
        if (error_stream) {
            fprintf(error_stream, "Errors from the OpenSSL error queue:\n");
            ERR_print_errors_fp(error_stream);
        }
        ERR_clear_error();
    }

    return exit_code;
}
