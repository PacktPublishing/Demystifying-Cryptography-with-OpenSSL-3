#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

int run_tls_server(
    const char* port,
    const char* server_keypair_fname,
    const char* server_cert_chain_fname,
    const char* trusted_cert_fname,
    FILE* error_stream);
int handle_accepted_connection(BIO* ssl_bio, FILE* error_stream);
BIO* construct_response(SSL* ssl);

int main(int argc, char** argv) {
    int exit_code = 0;

    if (argc != 5) {
        fprintf(stderr, "Usage: %s PORT SERVER_KEYPAIR_FILE SERVER_CERT_CHAIN_FILE TRUSTED_CERT_FILE\n", argv[0]);
        exit_code = 1;
        goto cleanup;
    }

    const char* port                    = argv[1];
    const char* server_keypair_fname    = argv[2];
    const char* server_cert_chain_fname = argv[3];
    const char* trusted_cert_fname      = argv[4];

    int err = run_tls_server(
        port,
        server_keypair_fname,
        server_cert_chain_fname,
        trusted_cert_fname,
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

int run_tls_server(
    const char* port,
    const char* server_keypair_fname,
    const char* server_cert_chain_fname,
    const char* trusted_cert_fname,
    FILE* error_stream) {

    int exit_code = 0;
    int err = 1;

    SSL_CTX* ctx = NULL;
    BIO* accept_bio = NULL;

    ERR_clear_error();

    ctx = SSL_CTX_new(TLS_server_method());
    assert(ctx);

    err = SSL_CTX_use_PrivateKey_file(ctx, server_keypair_fname, SSL_FILETYPE_PEM);
    if (err <= 0) {
        if (error_stream)
            fprintf(error_stream, "Could not load server keypair from file %s\n", server_keypair_fname);
        goto failure;
    }

    err = SSL_CTX_use_certificate_chain_file(ctx, server_cert_chain_fname);
    if (err <= 0) {
        if (error_stream)
            fprintf(error_stream, "Could not load server certificate chain from file %s\n", server_cert_chain_fname);
        goto failure;
    }

    err = SSL_CTX_check_private_key(ctx);
    if (err <= 0) {
        if (error_stream)
            fprintf(error_stream, "Server keypair does not match server certificate\n");
        goto failure;
    }

    err = SSL_CTX_load_verify_locations(ctx, trusted_cert_fname, NULL);
    if (err <= 0) {
        if (error_stream)
            fprintf(error_stream, "Could not load trusted certificates\n");
        goto failure;
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

    accept_bio = BIO_new_accept(port);
    assert(accept_bio);

    err = BIO_do_accept(accept_bio);
    if (err <= 0) {
        if (error_stream)
            fprintf(error_stream, "Could not bind to port %s and start listening for incoming TCP connections\n", port);
        goto failure;
    }

    if (ERR_peek_error()) {
        if (error_stream)
            fprintf(error_stream, "Unexpected error during TLS server setup\n");
        goto failure;
    }

    while (1) {
        printf("\n");
        printf("*** Listening on port %s\n", port);
        printf("\n");

        err = BIO_do_accept(accept_bio);
        if (err <= 0) {
            if (error_stream)
                fprintf(error_stream, "Error when trying to accept connection\n");
            if (ERR_peek_error()) {
                if (error_stream) {
                    fprintf(error_stream, "Errors from the OpenSSL error queue:\n");
                    ERR_print_errors_fp(error_stream);
                }
                ERR_clear_error();
            }

            continue;
        }

        BIO* socket_bio = BIO_pop(accept_bio);
        assert(socket_bio);

        BIO* ssl_bio = BIO_new_ssl(ctx, 0);
        assert(ssl_bio);

        BIO_push(ssl_bio, socket_bio);

        handle_accepted_connection(ssl_bio, error_stream);

    } // end of while loop

    goto cleanup;

failure:
    exit_code = 1;
cleanup:
    if (accept_bio)
        BIO_free_all(accept_bio);
    if (ctx)
        SSL_CTX_free(ctx);

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

int handle_accepted_connection(BIO* ssl_bio, FILE* error_stream) {
    int exit_code = 0;
    int err = 1;

    SSL* ssl = NULL;
    BIO* mem_bio = NULL;

    const size_t BUF_SIZE = 16 * 1024;
    char* in_buf = malloc(BUF_SIZE);
    assert(in_buf);

    ERR_clear_error();

    err = BIO_do_handshake(ssl_bio);
    if (err <= 0) {
        if (error_stream)
            fprintf(error_stream, "TLS handshaking error\n");
        goto failure;
    }

    err = BIO_get_ssl(ssl_bio, &ssl);
    assert(err == 1);
    assert(ssl);

    printf("*** Receiving from the client:\n");
    while ((SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN) != SSL_RECEIVED_SHUTDOWN) {
        int nbytes_read = BIO_get_line(ssl_bio, in_buf, BUF_SIZE);
        if (nbytes_read <= 0) {
            int ssl_error = SSL_get_error(ssl, nbytes_read);
            if (ssl_error == SSL_ERROR_ZERO_RETURN)
                break;

            if (error_stream)
                fprintf(error_stream, "Error %i while reading data from the client\n", ssl_error);
            goto failure;
        }

        fwrite(in_buf, 1, nbytes_read, stdout);
        if (!strcmp(in_buf, "\r\n") || !strcmp(in_buf, "\n"))
            break;
    }
    printf("*** Receiving from the client finished\n");

    mem_bio = construct_response(ssl);
    assert(mem_bio);

    char* response = NULL;
    long response_length = BIO_get_mem_data(mem_bio, &response);
    assert(response);
    assert(response_length > 0);

    printf("*** Sending to the client:\n");
    printf("%s", response);

    int nbytes_written = BIO_write(ssl_bio, response, response_length);
    if (nbytes_written != response_length) {
        if (error_stream)
            fprintf(error_stream, "Could not send all data to the client\n");
        goto failure;
    }
    printf("*** Sending to the client finished\n");

    BIO_ssl_shutdown(ssl_bio);

    goto cleanup;

failure:
    exit_code = 1;
cleanup:
    if (mem_bio)
        BIO_free(mem_bio);
    if (ssl_bio)
        BIO_free_all(ssl_bio);
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

BIO* construct_response(SSL* ssl) {
    BIO* mem_bio = BIO_new(BIO_s_mem());
    assert(mem_bio);

    const char* response_headers =
        "HTTP/1.0 200 OK\r\n"
        "Content-type: text/plain\r\n"
        "Connection: close\r\n"
        "Server: Example TLS server\r\n"
        "\r\n";
    BIO_puts(mem_bio, response_headers);

    X509* peer_cert = SSL_get_peer_certificate(ssl);

    if (peer_cert) {
        X509_NAME* peer_cert_subject = X509_get_subject_name(peer_cert);

        BIO_puts(mem_bio, "The TLS client certificate subject:\n");
        X509_NAME_print_ex(
            mem_bio,
            peer_cert_subject,
            0,
            XN_FLAG_ONELINE & ~ASN1_STRFLGS_ESC_MSB);
        BIO_puts(mem_bio, "\n");

        X509_free(peer_cert);
    } else {
        BIO_puts(mem_bio, "The TLS client has not provided a certificate\n");
    }

    return mem_bio;
}
