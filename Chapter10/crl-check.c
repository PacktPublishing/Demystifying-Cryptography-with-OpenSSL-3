#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

int run_tls_client(const char* hostname, const char* port, const char* trusted_cert_fname, FILE* error_stream);
STACK_OF(X509_CRL)* lookup_crls(const X509_STORE_CTX* x509_store, const X509_NAME* x509_name);
X509_CRL* download_crl_from_dist_point(const DIST_POINT* dist_point, FILE* error_stream);
X509_CRL* download_crl_from_http_url(const char* url);
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
    X509_STORE* x509_store = NULL;
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

    // Get X509_STORE.
    x509_store = SSL_CTX_get_cert_store(ctx);
    assert(x509_store);

    // Set CRL lookup callback.
    X509_STORE_set_lookup_crls(x509_store, lookup_crls);
    X509_STORE_set_flags(x509_store, X509_V_FLAG_CRL_CHECK);

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

STACK_OF(X509_CRL)* lookup_crls(const X509_STORE_CTX* x509_store_ctx, const X509_NAME* x509_name) {
    int ssl_ex_data_idx = SSL_get_ex_data_X509_STORE_CTX_idx();
    SSL* ssl = X509_STORE_CTX_get_ex_data(x509_store_ctx, ssl_ex_data_idx);
    FILE* error_stream = SSL_get_app_data(ssl);

    X509* current_cert = X509_STORE_CTX_get_current_cert(x509_store_ctx);
    if (!current_cert)
        return NULL;
    int depth = X509_STORE_CTX_get_error_depth(x509_store_ctx);
    X509_NAME* current_cert_subject = X509_get_subject_name(current_cert);

    fprintf(
        error_stream,
        "* lookup_crls() called with depth=%i\n",
        depth);
    fprintf(error_stream, "  Looking up CRL for certificate: ");
    X509_NAME_print_ex_fp(error_stream, current_cert_subject, 0, XN_FLAG_ONELINE & ~ASN1_STRFLGS_ESC_MSB);
    fprintf(error_stream, "\n");


    CRL_DIST_POINTS* crl_dist_points = (CRL_DIST_POINTS*) X509_get_ext_d2i(
        current_cert, NID_crl_distribution_points, NULL, NULL);
    if (!crl_dist_points)
        return NULL;

    int crl_dist_point_count = sk_DIST_POINT_num(crl_dist_points);
    for (int i = 0; i < crl_dist_point_count; i++) {
        DIST_POINT* dist_point = sk_DIST_POINT_value(crl_dist_points, i);
        X509_CRL* crl = download_crl_from_dist_point(dist_point, error_stream);
        if (!crl)
            continue;

        STACK_OF(X509_CRL)* crls = sk_X509_CRL_new_null();
        sk_X509_CRL_push(crls, crl);
        return crls;
    }

    return NULL;
}

X509_CRL* download_crl_from_dist_point(const DIST_POINT* dist_point, FILE* error_stream) {
    const DIST_POINT_NAME* dist_point_name = dist_point->distpoint;
    if (!dist_point_name || dist_point_name->type != 0)
        return NULL;

    const GENERAL_NAMES* general_names = dist_point_name->name.fullname;
    if (!general_names)
        return NULL;

    int general_name_count = sk_GENERAL_NAME_num(general_names);
    for (int i = 0; i < general_name_count; i++) {
        const GENERAL_NAME* general_name =
            sk_GENERAL_NAME_value(general_names, i);
        assert(general_name);

        int general_name_type = 0;
        const ASN1_STRING* general_name_asn1_string =
            (const ASN1_STRING*) GENERAL_NAME_get0_value(
                general_name, &general_name_type);
        assert(general_name_asn1_string);
        if (general_name_type != GEN_URI)
            continue;

        const char* url =
            (const char*) ASN1_STRING_get0_data(general_name_asn1_string);
        assert(url);

        // Skip non-HTTP URLs.
        const char* http_url_prefix = "http://";
        size_t http_url_prefix_len = strlen(http_url_prefix);
        if (strncmp(url, http_url_prefix, http_url_prefix_len))
            continue;

        fprintf(error_stream, "  Found CRL URL: %s\n", url);
        X509_CRL* crl = download_crl_from_http_url(url);
        if (!crl) {
            fprintf(error_stream, "  Failed to download CRL from %s\n", url);
            continue;
        }

        fprintf(error_stream, "  Downloaded CRL from %s\n", url);
        return crl;
    }

    return NULL;
}

X509_CRL* download_crl_from_http_url(const char* url) {
    BIO* bio = OSSL_HTTP_get(
        url,
        NULL /* proxy */,
        NULL /* no_proxy */,
        NULL /* wbio */,
        NULL /* rbio */,
        NULL /* bio_update_fn */,
        NULL /* arg */,
        65536 /* buf_size */,
        NULL /* headers */,
        NULL /* expected_content_type */,
        1 /* expect_asn1 */,
        50 * 1024 * 1024 /* max resp len */,
        60 /* timeout */);

    X509_CRL* crl = d2i_X509_CRL_bio(bio, NULL);

    BIO_free(bio);
    return crl;
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
        "* verify_callback() called with depth=%i, preverify_ok=%i, error_code=%i, error_string=%s\n",
        depth,
        preverify_ok,
        error_code,
        error_string);

    fprintf(error_stream, "  Certificate Subject: ");
    fwrite(bio_data, 1, bio_data_len, error_stream);
    fprintf(error_stream, "\n");

    BIO_free(mem_bio);

    if (error_code == X509_V_ERR_UNABLE_TO_GET_CRL)
        return 1;

    return preverify_ok;
}
