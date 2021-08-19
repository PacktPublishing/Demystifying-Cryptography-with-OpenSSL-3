#include <openssl/evp.h>
#include <openssl/rand.h>

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

const size_t KEY_LENGTH = 32;
const size_t IV_LENGTH = 12;
const size_t AUTH_TAG_LENGTH = 16;

int decrypt(FILE* in_file, FILE* out_file, const unsigned char* key, size_t auth_tag_pos, FILE* error_stream);

int main(int argc, char** argv) {
    int exit_code = 0;

    FILE* in_file  = NULL;
    FILE* out_file = NULL;
    unsigned char* key = NULL;

    if (argc != 4) {
        fprintf(stderr, "Usage: %s INPUT_FILE OUTPUT_FILE KEY_HEX\n", argv[0]);
        goto failure;
    }

    const char* in_fname  = argv[1];
    const char* out_fname = argv[2];
    const char* key_hex   = argv[3];

    long decoded_key_len = 0;
    key = OPENSSL_hexstr2buf(key_hex, &decoded_key_len);
    if (!key || decoded_key_len != KEY_LENGTH) {
        fprintf(stderr, "Wrong key \"%s\", must be %lu hex digits\n", key_hex, KEY_LENGTH * 2);
        goto failure;
    }

    struct stat in_file_stat;
    int err = stat(in_fname, &in_file_stat);
    if (err) {
        fprintf(stderr, "Could not stat input file \"%s\"\n", in_fname);
        goto failure;
    }

    size_t in_file_size = in_file_stat.st_size;
    if (in_file_size < IV_LENGTH + AUTH_TAG_LENGTH) {
        fprintf(stderr, "Input file \"%s\" is too short\n", in_fname);
        goto failure;
    }

    in_file = fopen(in_fname, "rb");
    if (!in_file) {
        fprintf(stderr, "Could not open input file \"%s\"\n", in_fname);
        goto failure;
    }

    out_file = fopen(out_fname, "wb");
    if (!out_file) {
        fprintf(stderr, "Could not open output file \"%s\"\n", out_fname);
        goto failure;
    }

    size_t auth_tag_pos = in_file_size - AUTH_TAG_LENGTH;
        err = decrypt(in_file, out_file, key, auth_tag_pos, stderr);
    if (err) {
        fprintf(stderr, "Decryption failed\n");
        goto failure;
    }

    fprintf(stderr, "Decryption succeeded\n");
    goto cleanup;

failure:
    exit_code = 1;
cleanup:
    OPENSSL_free(key);
    if (out_file)
        fclose(out_file);
    if (in_file)
        fclose(in_file);

    return exit_code;
}

int decrypt(FILE* in_file, FILE* out_file, const unsigned char* key, size_t auth_tag_pos, FILE* error_stream) {
    int exit_code = 0;

    unsigned char iv[IV_LENGTH];
    unsigned char auth_tag[AUTH_TAG_LENGTH];

    EVP_CIPHER_CTX* ctx = NULL;

    const size_t BUF_SIZE = 64 * 1024;
    const size_t BLOCK_SIZE = 16;
    unsigned char* in_buf  = malloc(BUF_SIZE);
    unsigned char* out_buf = malloc(BUF_SIZE + BLOCK_SIZE);
    if (!in_buf || !out_buf) {
        if (error_stream)
            fprintf(error_stream, "Could not allocate buffers\n");
        goto failure;
    }

    size_t in_nbytes = fread(iv, 1, IV_LENGTH, in_file);
    if (in_nbytes != IV_LENGTH || ferror(in_file)) {
        if (error_stream)
            fprintf(error_stream, "Could not read IV from input file\n");
        goto failure;
    }
    size_t current_pos = in_nbytes;

    ctx = EVP_CIPHER_CTX_new();
    int ok = EVP_DecryptInit(ctx, EVP_aes_256_gcm(), key, iv);
    if (!ctx || !ok) {
        if (error_stream)
            fprintf(error_stream, "Could not initialize decryption\n");
        goto failure;
    }

    while (current_pos < auth_tag_pos) {
        size_t in_nbytes_left = auth_tag_pos - current_pos;
        size_t in_nbytes_wanted = in_nbytes_left < BUF_SIZE ? in_nbytes_left : BUF_SIZE;

        in_nbytes = fread(in_buf, 1, in_nbytes_wanted, in_file);
        if (in_nbytes != in_nbytes_wanted || ferror(in_file)) {
            if (error_stream)
                fprintf(error_stream, "Could not read from input file\n");
            goto failure;
        }
        current_pos += in_nbytes;

        int out_nbytes = 0;
        ok = EVP_DecryptUpdate(ctx, out_buf, &out_nbytes, in_buf, in_nbytes);
        if (!ok) {
            if (error_stream)
                fprintf(error_stream, "Could not decrypt data chunk\n");
            goto failure;
        }

        fwrite(out_buf, 1, out_nbytes, out_file);
        if (ferror(out_file)) {
            if (error_stream)
                fprintf(error_stream, "Could not write to output file\n");
            goto failure;
        }
    }

    in_nbytes = fread(auth_tag, 1, AUTH_TAG_LENGTH, in_file);
    if (in_nbytes != AUTH_TAG_LENGTH || ferror(in_file)) {
        if (error_stream)
            fprintf(error_stream, "Could not read authentication tag from input file\n");
        goto failure;
    }

    ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AUTH_TAG_LENGTH, auth_tag);
    if (!ok) {
        if (error_stream)
            fprintf(error_stream, "Could not set authentication tag\n");
        exit_code = 1;
        goto failure;
    }

    int out_nbytes = 0;
    ok = EVP_DecryptFinal(ctx, out_buf, &out_nbytes);
    if (!ok) {
        if (error_stream)
            fprintf(error_stream, "Could not finalize decryption\n");
        goto failure;
    }

    fwrite(out_buf, 1, out_nbytes, out_file);
    if (ferror(out_file)) {
        if (error_stream)
            fprintf(error_stream, "Could not write to output file\n");
        goto failure;
    }

    goto cleanup;

failure:
    exit_code = 1;
cleanup:
    EVP_CIPHER_CTX_free(ctx);
    free(out_buf);
    free(in_buf);

    return exit_code;
}
