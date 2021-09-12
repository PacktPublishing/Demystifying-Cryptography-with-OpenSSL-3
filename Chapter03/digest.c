#include <openssl/evp.h>

#include <stdio.h>

const size_t DIGEST_LENGTH = 256 / 8;

int digest(FILE* in_file, unsigned char* md, FILE* error_stream);

int main(int argc, char** argv) {
    int exit_code = 0;

    FILE* in_file = NULL;
    unsigned char md[DIGEST_LENGTH];

    if (argc != 2) {
        fprintf(stderr, "Usage: %s INPUT_FILE\n", argv[0]);
        exit_code = 1;
        goto cleanup;
    }

    const char* in_fname  = argv[1];

    in_file = fopen(in_fname, "rb");
    if (!in_file) {
        fprintf(stderr, "Could not open input file \"%s\"\n", in_fname);
        goto failure;
    }

    int err = digest(in_file, md, stderr);
    if (err) {
        fprintf(stderr, "Message digest calculation failed\n");
        goto failure;
    }

    printf("SHA3-256(%s)= ", in_fname);
    for (size_t i = 0; i < DIGEST_LENGTH; ++i) {
        printf("%02x", md[i]);
    }
    printf("\n");

    goto cleanup;

failure:
    exit_code = 1;
cleanup:
    if (in_file)
        fclose(in_file);

    return exit_code;
}

int digest(FILE* in_file, unsigned char* md, FILE* error_stream) {
    int exit_code = 0;

    const size_t BUF_SIZE = 64 * 1024;
    unsigned char* in_buf = malloc(BUF_SIZE);

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    int ok = EVP_DigestInit(ctx, EVP_sha3_256());

    while (!feof(in_file)) {
        size_t in_nbytes = fread(in_buf, 1, BUF_SIZE, in_file);
        ok = EVP_DigestUpdate(ctx, in_buf, in_nbytes);
    }

    ok = EVP_DigestFinal(ctx, md, NULL);

    if (ferror(in_file)) {
        if (error_stream)
            fprintf(error_stream, "I/O error\n");
        goto failure;
    }

    if (!ok) {
        if (error_stream)
            fprintf(error_stream, "Message digest calculation error\n");
        goto failure;
    }

    goto cleanup;

failure:
    exit_code = 1;
cleanup:
    EVP_MD_CTX_free(ctx);
    free(in_buf);

    return exit_code;
}
