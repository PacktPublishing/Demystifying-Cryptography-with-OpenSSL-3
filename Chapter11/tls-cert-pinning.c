#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

int run_tls_client(const char* hostname, const char* port, const char* pinned_server_cert_fname, FILE* error_stream);
int cert_verify_callback(X509_STORE_CTX* x509_store_ctx, void* arg);

int main(int argc, char** argv) {
    int exit_code = 0;

    if (argc != 4) {
        fprintf(stderr, "Usage: %s HOSTNAME PORT PINNED_SERVER_CERT_FILE\n", argv[0]);
        exit_code = 1;
        goto cleanup;
    }

    const char* hostname                 = argv[1];
    const char* port                     = argv[2];
    const char* pinned_server_cert_fname = argv[3];

    int err = run_tls_client(hostname, port, pinned_server_cert_fname, stderr);
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

int run_tls_client(const char* hostname, const char* port, const char* pinned_server_cert_fname, FILE* error_stream) {
    int exit_code = 0;
    int err = 1;

    SSL_CTX* ctx = NULL;
    FILE* pinned_server_cert_file = NULL;
    X509* pinned_server_cert = NULL;
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

    pinned_server_cert_file = fopen(
        pinned_server_cert_fname, "rb");
    if (pinned_server_cert_file)
        pinned_server_cert = PEM_read_X509(
            pinned_server_cert_file, NULL, NULL, NULL);
    if (!pinned_server_cert) {
        if (error_stream)
            fprintf(error_stream, "Could not load pinned server certificate\n");
        goto failure;
    }

    SSL_CTX_set_cert_verify_callback(ctx, cert_verify_callback, pinned_server_cert);
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

    // Set application data for cert_verify_callback.
    err = SSL_set_app_data(ssl, error_stream);
    assert(err == 1);

    // TCP connect and TLS handshake.
    err = BIO_do_connect(ssl_bio);
    if (err <= 0) {
        if (error_stream)
            fprintf(error_stream, "Could not connect to server %s on port %s\n", hostname, port);
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

    int nbytes_written = BIO_write(ssl_bio, out_buf, request_length);
    if (nbytes_written != request_length) {
        if (error_stream)
            fprintf(error_stream, "Could not send all data to the server\n");
        goto failure;
    }
    printf("*** Sending to the server finished\n");

    printf("*** Receiving from the server:\n");
    while ((SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN) != SSL_RECEIVED_SHUTDOWN) {
        int nbytes_read = BIO_read(ssl_bio, in_buf, BUF_SIZE);
        if (nbytes_read <= 0) {
            int ssl_error = SSL_get_error(ssl, nbytes_read);
            if (ssl_error == SSL_ERROR_ZERO_RETURN)
                break;

            if (error_stream)
                fprintf(error_stream, "Error %i while reading data from the server\n", ssl_error);
            goto failure;
        }
        fwrite(in_buf, 1, nbytes_read, stdout);
    }
    printf("*** Receiving from the server finished\n");

    BIO_ssl_shutdown(ssl_bio);

    goto cleanup;

failure:
    exit_code = 1;
cleanup:
    if (ssl_bio)
        BIO_free_all(ssl_bio);
    if (pinned_server_cert)
        X509_free(pinned_server_cert);
    if (pinned_server_cert_file)
        fclose(pinned_server_cert_file);
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

int cert_verify_callback(X509_STORE_CTX* x509_store_ctx, void* arg) {
    int ssl_ex_data_idx = SSL_get_ex_data_X509_STORE_CTX_idx();
    SSL* ssl = X509_STORE_CTX_get_ex_data(x509_store_ctx, ssl_ex_data_idx);
    FILE* error_stream = SSL_get_app_data(ssl);

    X509* pinned_server_cert = arg;
    X509* actual_server_cert = X509_STORE_CTX_get0_cert(x509_store_ctx);

    if (error_stream) {
        X509_NAME* pinned_cert_subject = X509_get_subject_name(pinned_server_cert);
        X509_NAME* actual_cert_subject = X509_get_subject_name(actual_server_cert);

        fprintf(
            error_stream,
            "* cert_verify_callback() called with the following pinned certificate:\n");
        X509_NAME_print_ex_fp(error_stream, pinned_cert_subject, 2, XN_FLAG_ONELINE & ~ASN1_STRFLGS_ESC_MSB);
        fprintf(error_stream, "\n");

        fprintf(
            error_stream,
            "  The server presented the following certificate:\n");
        X509_NAME_print_ex_fp(error_stream, actual_cert_subject, 2, XN_FLAG_ONELINE & ~ASN1_STRFLGS_ESC_MSB);
        fprintf(error_stream, "\n");
    }


    int cmp = X509_cmp(pinned_server_cert, actual_server_cert);

    X509_STORE_CTX_set_current_cert(x509_store_ctx, actual_server_cert);
    X509_STORE_CTX_set_depth(x509_store_ctx, 0);

    if (cmp == 0) {
        if (error_stream)
            fprintf(error_stream, "  The certificates match. Proceeding with the TLS connection.\n");

        X509_STORE_CTX_set_error(x509_store_ctx, X509_V_OK);
        return 1;
    } else {
        if (error_stream)
            fprintf(error_stream, "  The certificates do not match. Aborting the TLS connection.\n");

        X509_STORE_CTX_set_error(x509_store_ctx, X509_V_ERR_APPLICATION_VERIFICATION);
        return 0;
    }
}
