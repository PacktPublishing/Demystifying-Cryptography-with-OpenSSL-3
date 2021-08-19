#include "openssl/ssl.h"
#include <stdio.h>

int main() {
    printf("Intitializing OpenSSL...\n");
    OPENSSL_init_ssl(0, NULL);

    printf("Unintitializing OpenSSL...\n");
    OPENSSL_cleanup();

    printf("Done.\n");
    return 0;
}
