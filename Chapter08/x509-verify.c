#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/safestack.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <stdio.h>
#include <string.h>

int verify(const char* trusted_cert_fname, FILE* untrusted_cert_file, FILE* target_cert_file, FILE* error_stream);

int main(int argc, char** argv) {
    int exit_code = 0;

    FILE* untrusted_cert_file = NULL;
    FILE* target_cert_file    = NULL;

    if (argc != 4) {
        fprintf(stderr, "Usage: %s TRUSTED_CERT_FILE UNTRUSTED_CERT_FILE TARGET_CERT_FILE\n", argv[0]);
        exit_code = 1;
        goto cleanup;
    }

    const char* trusted_cert_fname   = argv[1];
    const char* untrusted_cert_fname = argv[2];
    const char* target_cert_fname    = argv[3];

    untrusted_cert_file = fopen(untrusted_cert_fname, "rb");
    if (!untrusted_cert_file) {
        fprintf(stderr, "Could not open untrusted certificate file \"%s\"\n", untrusted_cert_fname);
        goto failure;
    }

    target_cert_file = fopen(target_cert_fname, "rb");
    if (!target_cert_file) {
        fprintf(stderr, "Could not open target certificate file \"%s\"\n", target_cert_fname);
        goto failure;
    }

    int err = verify(trusted_cert_fname, untrusted_cert_file, target_cert_file, stderr);
    if (err) {
        fprintf(stderr, "Verification failed\n");
        goto failure;
    }

    fprintf(stderr, "Verification succeeded\n");
    goto cleanup;

failure:
    exit_code = 1;
cleanup:
    if (target_cert_file)
        fclose(target_cert_file);
    if (untrusted_cert_file)
        fclose(untrusted_cert_file);

    return exit_code;
}

int verify(const char* trusted_cert_fname, FILE* untrusted_cert_file, FILE* target_cert_file, FILE* error_stream) {
    int exit_code = 0;
    int err = 1;

    X509_STORE_CTX* ctx = NULL;
    X509_STORE* trusted_store = NULL;
    STACK_OF(X509)* untrusted_stack = NULL;
    X509* target_cert = NULL;

    ERR_clear_error();

    trusted_store = X509_STORE_new();
    err = X509_STORE_load_file(trusted_store, trusted_cert_fname);
    if (err != 1) {
        if (error_stream)
            fprintf(error_stream, "Could not load trusted certificates\n");
        goto failure;
    }

    fseek(untrusted_cert_file, 0, SEEK_END);
    long untrusted_cert_file_len = ftell(untrusted_cert_file);
    fseek(untrusted_cert_file, 0, SEEK_SET);

    untrusted_stack = sk_X509_new_null();
    while (ftell(untrusted_cert_file) < untrusted_cert_file_len) {
        X509* untrusted_cert = PEM_read_X509(untrusted_cert_file, NULL, NULL, NULL);
        if (err != 1) {
            if (error_stream)
                fprintf(error_stream, "Could not load untrusted certificates\n");
            goto failure;
        }

        sk_X509_push(untrusted_stack, untrusted_cert);
    }

    target_cert = PEM_read_X509(target_cert_file, NULL, NULL, NULL);
    if (err != 1) {
        if (error_stream)
            fprintf(error_stream, "Could not load target certificate\n");
        goto failure;
    }

    ctx = X509_STORE_CTX_new();
    err = X509_STORE_CTX_init(ctx, trusted_store, target_cert, untrusted_stack);
    err = X509_verify_cert(ctx);

    if (ferror(untrusted_cert_file) || ferror(target_cert_file)) {
        if (error_stream)
            fprintf(error_stream, "I/O error\n");
        goto failure;
    }

    if (err != 1) {
        if (error_stream) {
            int error_code = X509_STORE_CTX_get_error(ctx);
            const char* error_string = X509_verify_cert_error_string(error_code);
            fprintf(error_stream, "X509 verification error: %s\n", error_string);
        }
        goto failure;
    }

    goto cleanup;

failure:
    exit_code = 1;
cleanup:
    X509_STORE_CTX_free(ctx);
    X509_free(target_cert);
    sk_X509_pop_free(untrusted_stack, X509_free);
    X509_STORE_free(trusted_store);

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
