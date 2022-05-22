#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

int run_tls_client(const char* hostname, const char* port, const char* trusted_cert_fname, FILE* error_stream);
int verify_callback(int preverify_ok, X509_STORE_CTX* x509_store_ctx);

int main(int argc, char** argv) {
    int exit_code = 0;

    if (argc != 3 && argc != 4) {
        fprintf(stderr, "Usage: %s HOSTNAME PORT [TRUSTED_CERT_FILE]\n", argv[0]);
        exit_code = 1;
        goto cleanup;
    }

    const char* hostname           = argv[1];
    const char* port               = argv[2];
    const char* trusted_cert_fname = argv[3];

    int err = run_tls_client(hostname, port, trusted_cert_fname, stderr);
    if (err) {
        fprintf(stderr, "TLS communication failed\n");
        goto failure;
    }

    fprintf(stderr, "TLS communication succeeded\n");
    goto cleanup;

failure:
    exit_code = 1;
cleanup:
    return exit_code;
}

int run_tls_client(const char* hostname, const char* port, const char* trusted_cert_fname, FILE* error_stream) {
    int exit_code = 0;
    int err = 1;

    SSL_CTX* ctx = NULL;
    BIO* ssl_bio = NULL;
    SSL* ssl = NULL;

    const size_t BUF_SIZE = 16 * 1024;
    char* in_buf  = malloc(BUF_SIZE);
    assert(in_buf);
    char* out_buf = malloc(BUF_SIZE);
    assert(out_buf);

    ERR_clear_error();

    ctx = SSL_CTX_new(TLS_client_method());
    assert(ctx);

    if (trusted_cert_fname)
        err = SSL_CTX_load_verify_locations(ctx, trusted_cert_fname, NULL);
    else
        err = SSL_CTX_set_default_verify_paths(ctx);
    if (err <= 0) {
        if (error_stream)
            fprintf(error_stream, "Could not load trusted certificates\n");
        goto failure;
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

    // Create an SSL connect BIO.
    ssl_bio = BIO_new_ssl_connect(ctx);
    assert(ssl_bio);

    // Set hostname for connection.
    BIO_set_conn_hostname(ssl_bio, hostname);
    BIO_set_conn_port(ssl_bio, port);

    // Get SSL object.
    err = BIO_get_ssl(ssl_bio, &ssl);
    assert(err == 1);
    assert(ssl);

    // Set hostname for SNI extension.
    err = SSL_set_tlsext_host_name(ssl, hostname);
    assert(err == 1);

    // Set hostname for certificate hostname verification.
    err = SSL_set1_host(ssl, hostname);
    assert(err == 1);

    // Set application data for verify_callback.
    err = SSL_set_app_data(ssl, error_stream);

    // TCP connect and TLS handshake.
    err = BIO_do_connect(ssl_bio);
    if (err <= 0) {
        if (error_stream)
            fprintf(error_stream, "Could not connect to server %s on port %s\n", hostname, port);
        goto failure;
    }

    BIO_ssl_shutdown(ssl_bio);

    goto cleanup;

failure:
    exit_code = 1;
cleanup:
    if (ssl_bio)
        BIO_free_all(ssl_bio);
    if (ctx)
        SSL_CTX_free(ctx);
    free(out_buf);
    free(in_buf);

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

int verify_callback(int preverify_ok, X509_STORE_CTX* x509_store_ctx) {
    int ssl_ex_data_idx = SSL_get_ex_data_X509_STORE_CTX_idx();
    SSL* ssl = X509_STORE_CTX_get_ex_data(x509_store_ctx, ssl_ex_data_idx);
    FILE* error_stream = SSL_get_app_data(ssl);

    int depth = X509_STORE_CTX_get_error_depth(x509_store_ctx);
    int error_code = preverify_ok ? X509_V_OK : X509_STORE_CTX_get_error(x509_store_ctx);
    const char* error_string = X509_verify_cert_error_string(error_code);

    X509* current_cert = X509_STORE_CTX_get_current_cert(x509_store_ctx);
    X509_NAME* current_cert_subject = X509_get_subject_name(current_cert);

    BIO* mem_bio = BIO_new(BIO_s_mem());
    X509_NAME_print_ex(mem_bio, current_cert_subject, 0, XN_FLAG_ONELINE & ~ASN1_STRFLGS_ESC_MSB);
    char* bio_data = NULL;
    long bio_data_len = BIO_get_mem_data(mem_bio, &bio_data);

    fprintf(
        error_stream,
        "verify_callback() called with depth=%i, preverify_ok=%i, error_code=%i, error_string=%s\n",
        depth,
        preverify_ok,
        error_code,
        error_string);

    fprintf(error_stream, "Certificate Subject: ");
    fwrite(bio_data, 1, bio_data_len, error_stream);
    fprintf(error_stream, "\n");

    BIO_free(mem_bio);
    X509_free(current_cert);

    return preverify_ok;
}
