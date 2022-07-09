#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

int run_tls_client(const char* hostname, const char* port, const char* trusted_cert_fname, FILE* error_stream);

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

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

    ssl_bio = BIO_new_ssl_connect(ctx);
    assert(ssl_bio);
    // Set hostname for connection.
    BIO_set_conn_hostname(ssl_bio, hostname);
    BIO_set_conn_port(ssl_bio, port);

    err = BIO_get_ssl(ssl_bio, &ssl);
    assert(err == 1);
    assert(ssl);
    // Set hostname for SNI extension.
    err = SSL_set_tlsext_host_name(ssl, hostname);
    assert(err == 1);
    // Set hostname for certificate hostname verification.
    err = SSL_set1_host(ssl, hostname);
    assert(err == 1);

    err = BIO_set_nbio(ssl_bio, 1);
    if (err <= 0) {
        if (error_stream)
            fprintf(
                error_stream,
                "Could not enable non-blocking mode\n");
        goto failure;
    }

    const time_t TIMEOUT_SECONDS = 10;
    const unsigned int NAP_MILLISECONDS = 100;
    time_t deadline = time(NULL) + TIMEOUT_SECONDS;

    // TCP connect and TLS handshake.
    err = BIO_do_connect(ssl_bio);

    while (err <= 0 && BIO_should_retry(ssl_bio)) {
        int wait_err = BIO_wait(
            ssl_bio,
            deadline,
            NAP_MILLISECONDS);
        if (wait_err != 1)
            break;

        err = BIO_do_connect(ssl_bio);
    }

    if (err <= 0) {
        if (error_stream)
            fprintf(
                error_stream,
                "Could not connect to server %s on port %s\n",
                hostname,
                port);
        goto failure;
    }

    snprintf(
        out_buf,
        BUF_SIZE,
        "GET / HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Connection: close\r\n"
        "User-Agent: Example TLS client\r\n"
        "\r\n",
        hostname);
    int request_length = strlen(out_buf);

    printf("*** Sending to the server:\n");
    printf("%s", out_buf);

    int nbytes_written_total = 0;
    while (nbytes_written_total < request_length) {
        int nbytes_written = BIO_write(
            ssl_bio,
            out_buf + nbytes_written_total,
            request_length - nbytes_written_total);

        if (nbytes_written > 0) {
            nbytes_written_total += nbytes_written;
            continue;
        }

        if (BIO_should_retry(ssl_bio)) {
            BIO_wait(
                ssl_bio,
                deadline,
                NAP_MILLISECONDS);
            continue;
        }

        if (error_stream)
            fprintf(
                error_stream,
                "Could not send all data to the server\n");
        goto failure;
    }

    printf("*** Sending to the server finished\n");

    printf("*** Receiving from the server:\n");
    while ((SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN)
           != SSL_RECEIVED_SHUTDOWN) {

        int nbytes_read = BIO_read(ssl_bio, in_buf, BUF_SIZE);

        if (nbytes_read > 0) {
            fwrite(in_buf, 1, nbytes_read, stdout);
            continue;
        }

        if (BIO_should_retry(ssl_bio)) {
            err = BIO_wait(
                ssl_bio,
                deadline,
                NAP_MILLISECONDS);
            continue;
        }

        int ssl_error = SSL_get_error(ssl, nbytes_read);
        if (ssl_error == SSL_ERROR_ZERO_RETURN)
            break;

        if (error_stream)
            fprintf(
                error_stream,
                "Error %i while reading data "
                "from the server\n",
                ssl_error);
        goto failure;
    }
    printf("*** Receiving from the server finished\n");

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
