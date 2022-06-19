#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/ssl.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

int run_tls_client(
    const char* hostname,
    const char* port,
    const char* trusted_cert_fname,
    const char* client_cert_fname,
    const char* client_cert_password,
    FILE* error_stream);

int load_client_certificate(
    const char* client_cert_fname,
    const char* client_cert_password,
    SSL_CTX* ctx,
    FILE* error_stream);

int main(int argc, char** argv) {
    int exit_code = 0;

    if (argc != 6) {
        fprintf(stderr, "Usage: %s HOSTNAME PORT TRUSTED_CERT_FILE CLIENT_CERT_FILE CLIENT_CERT_PASSWORD\n", argv[0]);
        exit_code = 1;
        goto cleanup;
    }

    const char* hostname             = argv[1];
    const char* port                 = argv[2];
    const char* trusted_cert_fname   = argv[3];
    const char* client_cert_fname    = argv[4];
    const char* client_cert_password = argv[5];

    int err = run_tls_client(
        hostname,
        port,
        trusted_cert_fname,
        client_cert_fname,
        client_cert_password,
        stderr);
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

int run_tls_client(
    const char* hostname,
    const char* port,
    const char* trusted_cert_fname,
    const char* client_cert_fname,
    const char* client_cert_password,
    FILE* error_stream) {

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

    err = SSL_CTX_load_verify_locations(ctx, trusted_cert_fname, NULL);
    if (err <= 0) {
        if (error_stream)
            fprintf(error_stream, "Could not load trusted certificates\n");
        goto failure;
    }

    int load_exit_code = load_client_certificate(
        client_cert_fname,
        client_cert_password,
        ctx,
        error_stream);
    if (load_exit_code != 0)
        goto failure;

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

int load_client_certificate(
    const char* client_cert_fname,
    const char* client_cert_password,
    SSL_CTX* ctx,
    FILE* error_stream) {

    int exit_code = 0;

    BIO* client_cert_bio = NULL;
    PKCS12* pkcs12 = NULL;
    EVP_PKEY* pkey = NULL;
    X509* cert = NULL;
    STACK_OF(X509)* cert_chain = NULL;

    client_cert_bio = BIO_new_file(client_cert_fname, "rb");
    if (!client_cert_bio) {
        if (error_stream)
            fprintf(
                error_stream,
                "Could not open client certificate file %s\n",
                client_cert_fname);
        goto failure;
    }

    pkcs12 = d2i_PKCS12_bio(client_cert_bio, NULL);
    if (!pkcs12) {
        if (error_stream)
            fprintf(
                error_stream,
                "Could not load client certificate from file %s\n",
                client_cert_fname);
        goto failure;
    }

    int res = PKCS12_verify_mac(
        pkcs12,
        client_cert_password,
        strlen(client_cert_password));
    if (res != 1) {
        if (error_stream)
            fprintf(
                error_stream,
                "Invalid password was provided for client certificate file %s\n",
                client_cert_fname);
        goto failure;
    }

    res = PKCS12_parse(
        pkcs12,
        client_cert_password,
        &pkey,
        &cert,
        &cert_chain);
    if (res != 1) {
        if (error_stream)
            fprintf(
                error_stream,
                "Could not decode client certificate loaded from file %s\n",
                client_cert_fname);
        goto failure;
    }

    res = SSL_CTX_use_cert_and_key(
        ctx,
        cert,
        pkey,
        cert_chain,
        1);
    if (res != 1) {
        if (error_stream)
            fprintf(
                error_stream,
                "Could not use client certificate loaded from file %s\n",
                client_cert_fname);
        goto failure;
    }

    res = SSL_CTX_check_private_key(ctx);
    if (res != 1) {
        if (error_stream)
            fprintf(error_stream, "Client keypair does not match client certificate\n");
        goto failure;
    }

    goto cleanup;

failure:
    exit_code = 1;
cleanup:
    if (cert_chain)
        sk_X509_pop_free(cert_chain, X509_free);
    if (cert)
        X509_free(cert);
    if (pkey)
        EVP_PKEY_free(pkey);
    if (pkcs12)
        PKCS12_free(pkcs12);
    if (client_cert_bio)
        BIO_free(client_cert_bio);

    return exit_code;
}
