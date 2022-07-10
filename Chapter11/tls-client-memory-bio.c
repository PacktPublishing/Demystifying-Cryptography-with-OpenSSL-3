#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

int run_tls_client(
    const char* hostname,
    const char* port,
    const char* trusted_cert_fname,
    FILE* error_stream);

int service_bios(
    BIO* mem_rbio,
    BIO* mem_wbio,
    BIO* tcp_bio,
    int want_read);

const size_t BUF_SIZE = 16 * 1024;

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
    BIO* tcp_bio = NULL;
    BIO* mem_rbio = NULL;
    BIO* mem_wbio = NULL;
    SSL* ssl = NULL;

    char* in_buf  = malloc(BUF_SIZE);
    assert(in_buf);
    char* out_buf = malloc(BUF_SIZE);
    assert(out_buf);

    ERR_clear_error();

    ctx = SSL_CTX_new(TLS_client_method());
    assert(ctx);

    if (trusted_cert_fname)
        err = SSL_CTX_load_verify_locations(
            ctx, trusted_cert_fname, NULL);
    else
        err = SSL_CTX_set_default_verify_paths(ctx);
    if (err <= 0) {
        if (error_stream)
            fprintf(
                error_stream,
                "Could not load trusted certificates\n");
        goto failure;
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    // Set hostname for connection.
    tcp_bio = BIO_new_connect(hostname);
    assert(tcp_bio);
    BIO_set_conn_port(tcp_bio, port);

    err = BIO_do_connect(tcp_bio);
    if (err <= 0) {
        if (error_stream)
            fprintf(
                error_stream,
                "Could not connect to server %s on port %s\n",
                hostname,
                port);
        goto failure;
    }

    mem_rbio = BIO_new(BIO_s_mem());
    assert(mem_rbio);
    BIO_set_mem_eof_return(mem_rbio, -1);

    mem_wbio = BIO_new(BIO_s_mem());
    assert(mem_wbio);
    BIO_set_mem_eof_return(mem_wbio, -1);

    ssl = SSL_new(ctx);
    assert(ssl);
    SSL_set_bio(ssl, mem_rbio, mem_wbio);

    // Set hostname for SNI extension.
    err = SSL_set_tlsext_host_name(ssl, hostname);
    assert(err == 1);
    // Set hostname for certificate hostname verification.
    err = SSL_set1_host(ssl, hostname);
    assert(err == 1);

    // TLS handshake.
    while (1) {
        err = SSL_connect(ssl);

        int ssl_error = SSL_get_error(ssl, err);
        if (ssl_error == SSL_ERROR_WANT_READ
            || ssl_error == SSL_ERROR_WANT_WRITE
            || BIO_pending(mem_wbio)) {

            int service_bios_err = service_bios(
                mem_rbio, mem_wbio, tcp_bio, SSL_want_read(ssl));
            if (service_bios_err != 1) {
                if (error_stream)
                    fprintf(
                        error_stream,
                        "Socket error during TLS handshake\n");
                goto failure;
            }
            continue;
        }
        break;
    }

    if (err <= 0) {
        if (error_stream)
            fprintf(
                error_stream,
                "TLS error %i during TLS handshake\n",
                SSL_get_error(ssl, err));
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
        int nbytes_written = SSL_write(
            ssl,
            out_buf + nbytes_written_total,
            request_length - nbytes_written_total);

        if (nbytes_written > 0) {
            nbytes_written_total += nbytes_written;
            continue;
        }

        int ssl_error = SSL_get_error(ssl, err);
        if (ssl_error == SSL_ERROR_WANT_READ
            || ssl_error == SSL_ERROR_WANT_WRITE
            || BIO_pending(mem_wbio)) {

            int service_bios_err = service_bios(
                mem_rbio, mem_wbio, tcp_bio, SSL_want_read(ssl));
            if (service_bios_err != 1) {
                if (error_stream)
                    fprintf(
                        error_stream,
                        "Socket error while sending data "
                        "to the server\n");
                goto failure;
            }
            continue;
        }

        if (error_stream)
            fprintf(
                error_stream,
                "TLS error %i while reading data "
                "to the server\n",
                ssl_error);
        goto failure;
    }
    printf("*** Sending to the server finished\n");

    printf("*** Receiving from the server:\n");
    while ((SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN)
           != SSL_RECEIVED_SHUTDOWN) {

        int service_bios_err = 1;
        if (!BIO_pending(mem_rbio))
            service_bios_err = service_bios(
                mem_rbio, mem_wbio, tcp_bio, 1);
        if (service_bios_err != 1) {
            if (error_stream)
                fprintf(
                    error_stream,
                    "Socket error while reading data "
                    "from the server\n");
            goto failure;
        }

        int nbytes_read = SSL_read(ssl, in_buf, BUF_SIZE);
        if (nbytes_read > 0) {
            fwrite(in_buf, 1, nbytes_read, stdout);
            continue;
        }

        int ssl_error = SSL_get_error(ssl, err);

        if (ssl_error == SSL_ERROR_NONE
            || ssl_error == SSL_ERROR_WANT_READ
            || ssl_error == SSL_ERROR_WANT_WRITE
            || BIO_pending(mem_wbio))
            continue;

        if (ssl_error == SSL_ERROR_ZERO_RETURN)
            break;

        if (error_stream)
            fprintf(
                error_stream,
                "TLS error %i while reading data "
                "from the server\n",
                ssl_error);
        goto failure;
    }
    printf("*** Receiving from the server finished\n");

    while (1) {
        err = SSL_shutdown(ssl);

        int ssl_error = SSL_get_error(ssl, err);
        if (ssl_error == SSL_ERROR_WANT_READ
            || ssl_error == SSL_ERROR_WANT_WRITE
            || BIO_pending(mem_wbio)) {

            int service_bios_err = service_bios(
                mem_rbio, mem_wbio, tcp_bio, SSL_want_read(ssl));
            if (service_bios_err != 1) {
                if (error_stream)
                    fprintf(
                        error_stream,
                        "Socket error during TLS shutdown\n");
                goto failure;
            }
            continue;
        }

        break;
    }

    if (err != 1) {
        if (error_stream)
            fprintf(
                error_stream,
                "TLS error during TLS shutdown\n");
        goto failure;
    }

    goto cleanup;

failure:
    exit_code = 1;
cleanup:
    if (ssl)
        SSL_free(ssl);
    if (tcp_bio)
        BIO_free_all(tcp_bio);
    if (ctx)
        SSL_CTX_free(ctx);
    free(out_buf);
    free(in_buf);

    if (ERR_peek_error()) {
        exit_code = 1;
        if (error_stream) {
            fprintf(
                error_stream,
                "Errors from the OpenSSL error queue:\n");
            ERR_print_errors_fp(error_stream);
        }
        ERR_clear_error();
    }

    return exit_code;
}

int service_bios(
    BIO* mem_rbio,
    BIO* mem_wbio,
    BIO* tcp_bio,
    int want_read) {

    int err = 1;

    char* in_buf  = malloc(BUF_SIZE);
    assert(in_buf);
    char* out_buf = malloc(BUF_SIZE);
    assert(out_buf);

    while (BIO_pending(mem_wbio)) {
        int nbytes_read =
            BIO_read(mem_wbio, out_buf, BUF_SIZE);

        int nbytes_written_total = 0;
        while (nbytes_written_total < nbytes_read) {
            int nbytes_written =
                BIO_write(tcp_bio, out_buf, nbytes_read);

            if (nbytes_written > 0) {
                nbytes_written_total += nbytes_written;
                continue;
            } else {
                goto failure;
            }
        }
    }

    if (want_read) {
        int nbytes_read =
            BIO_read(tcp_bio, in_buf, BUF_SIZE);

        if (nbytes_read > 0) {
            BIO_write(mem_rbio, in_buf, nbytes_read);
        } else {
            goto failure;
        }
    }

    goto cleanup;

failure:
    err = -1;
cleanup:
    free(out_buf);
    free(in_buf);

    return err;
}
