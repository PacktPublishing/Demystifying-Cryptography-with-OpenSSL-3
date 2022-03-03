#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/pem.h>

#include <stdio.h>
#include <string.h>

int sign(FILE* in_file, FILE* sig_file, FILE* pkey_file, FILE* error_stream);

int main(int argc, char** argv) {
    int exit_code = 0;

    FILE* in_file   = NULL;
    FILE* sig_file  = NULL;
    FILE* pkey_file = NULL;

    if (argc != 4) {
        fprintf(stderr, "Usage: %s INPUT_FILE SIGNATURE_FILE KEYPAIR_FILE\n", argv[0]);
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

    sig_file = fopen(sig_fname, "wb");
    if (!sig_file) {
        fprintf(stderr, "Could not open sig_buf file \"%s\"\n", sig_fname);
        goto failure;
    }

    pkey_file = fopen(pkey_fname, "rb");
    if (!pkey_file) {
        fprintf(stderr, "Could not open keypair file \"%s\"\n", pkey_fname);
        goto failure;
    }

    int err = sign(in_file, sig_file, pkey_file, stderr);
    if (err) {
        fprintf(stderr, "Signing failed\n");
        goto failure;
    }

    fprintf(stderr, "Signing succeeded\n");
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

int sign(FILE* in_file, FILE* sig_file, FILE* pkey_file, FILE* error_stream) {
    int exit_code = 0;
    int err = 1;

    const size_t BUF_SIZE = 64 * 1024;

    EVP_PKEY* pkey = NULL;
    EVP_MD_CTX* md_ctx = NULL;

    unsigned char* in_buf  = NULL;
    unsigned char* sig_buf = NULL;

    ERR_clear_error();

    pkey = PEM_read_PrivateKey(pkey_file, NULL, NULL, NULL);
    if (!pkey) {
        if (error_stream)
            fprintf(error_stream, "Could not load keypair\n");
        goto failure;
    }

    md_ctx = EVP_MD_CTX_new();
    err = EVP_DigestSignInit_ex(
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
        err = EVP_DigestSignUpdate(md_ctx, in_buf, in_nbytes);
    }

    size_t sig_len = 0;
    err = EVP_DigestSignFinal(md_ctx, NULL, &sig_len);

    sig_buf = malloc(sig_len);
    err = EVP_DigestSignFinal(md_ctx, sig_buf, &sig_len);

    fwrite(sig_buf, 1, sig_len, sig_file);

    if (ferror(in_file) || ferror(sig_file) || ferror(pkey_file)) {
        if (error_stream)
            fprintf(error_stream, "I/O error\n");
        goto failure;
    }

    if (err <= 0) {
        if (error_stream)
            fprintf(error_stream, "EVP_API error\n");
        goto failure;
    }

    goto cleanup;

failure:
    exit_code = 1;
cleanup:
    free(sig_buf);
    free(in_buf);
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);

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
