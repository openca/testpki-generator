/*
 * Mermaid TLS Example
 * Copyright 2022-2024 The OpenCA Project Authors. All Rights Reserved.
 * 
 * This is a simple example of a server that uses Mermaid TLS to secure the
 * communication with a client by using hybrid post-quantum cryptography.
 * 
 * The example is based on the OpenSSL example "s_server.c" and has been
 * modified to implement Mermaid TLS extensions.
 */
/*
 *  Copyright 2022-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License").  You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://www.openssl.org/source/license.html
 */

#include "mermaid_client.h"

typedef unsigned char   bool;
#define true            1
#define false           0

/*
 * This flag won't be useful until both accept/read (TCP & SSL) methods
 * can be called with a timeout. TBD.
 */
static volatile bool    server_running = true;

static int create_socket(void)
{
    int s;

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    return s;
}

static SSL_CTX* create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_client_method();

    ctx = SSL_CTX_new(method);
    if (ctx == NULL) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

static void usage(void)
{
    printf("\n\tUSAGE: mermaid-client <config_dir> <server_addr> <port_number>\n\n");
    exit(EXIT_FAILURE);
}

#define BUFFERSIZE 1024
int main(int argc, char **argv)
{
    int result;

    SSL_CTX *ssl_ctx = NULL;
    SSL *ssl = NULL;

    int client_skt = -1;

    /* used by fgets */
    char buffer[BUFFERSIZE];
    char *txbuf;

    char rxbuf[128];
    size_t rxcap = sizeof(rxbuf);
    int rxlen;

    char *rem_server_ip = NULL;
    char *config_dir = NULL;
    int rem_server_port = 9000;

    struct sockaddr_in addr;
// #if defined(OPENSSL_SYS_CYGWIN) || defined(OPENSSL_SYS_WINDOWS)
//     int addr_len = sizeof(addr);
// #else
//     unsigned int addr_len = sizeof(addr);
// #endif

#if !defined (OPENSSL_SYS_WINDOWS)
    /* ignore SIGPIPE so that server can continue running when client pipe closes abruptly */
    signal(SIGPIPE, SIG_IGN);
#endif

    /* Splash */
    printf("\nMermaid TLS Echo : Simple Echo Client : %s : %s\n\n",
        __DATE__, __TIME__);

    /* Need to know if client or server */
    if (argc < 3) {
        usage();
        /* NOTREACHED */
    }
    
    config_dir = argv[1];
    if (config_dir == NULL) {
        usage();
        /* NOTREACHED */
    }

    rem_server_ip = argv[2];
    if (rem_server_ip == NULL) {
        usage();
        /* NOTREACHED */
    }

    rem_server_port = atoi(argv[3]);
    if (rem_server_port <= 0) {
        usage();
        /* NOTREACHED */
    }

    /* Create context used by both client and server */
    ssl_ctx = create_context();

    
        // /* Configure client context so we verify the server correctly */
        // configure_client_context(ssl_ctx);

    char chain_filename[512] = { 0x0 };
    sprintf(chain_filename, "%s/chains/client.chain", config_dir);

        /* Set the key and cert */
        if (SSL_CTX_use_certificate_chain_file(ssl_ctx, chain_filename) <= 0) {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }

    char key_filename[512] = { 0x0 };
    sprintf(key_filename, "%s/private/client.private", config_dir);

        if (SSL_CTX_use_PrivateKey_file(ssl_ctx, &key_filename[0], SSL_FILETYPE_ASN1) <= 0) {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }

    /*
     * Configure the client to abort the handshake if certificate verification
     * fails
     */
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);

    /*
     * In a real application you would probably just use the default system certificate trust store and call:
     *     SSL_CTX_set_default_verify_paths(ctx);
     * In this demo though we are using a self-signed certificate, so the client must trust it directly.
     */
    char trust_filename[512] = { 0x0 };
    sprintf(trust_filename, "%s/certs/trust.store", config_dir);

    if (!SSL_CTX_load_verify_file(ssl_ctx, trust_filename)) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

        /* Create "bare" socket */
        client_skt = create_socket();
        /* Set up connect address */
        addr.sin_family = AF_INET;
        inet_pton(AF_INET, rem_server_ip, &addr.sin_addr.s_addr);
        addr.sin_port = htons(rem_server_port);
        /* Do TCP connect with server */
        if (connect(client_skt, (struct sockaddr*) &addr, sizeof(addr)) != 0) {
            perror("Unable to TCP connect to server");
            goto exit;
        } else {
            printf("TCP connection to server successful\n");
        }

        /* Create client SSL structure using dedicated client socket */
        ssl = SSL_new(ssl_ctx);
        if (!SSL_set_fd(ssl, client_skt)) {
            ERR_print_errors_fp(stderr);
            goto exit;
        }
        /* Set hostname for SNI */
        SSL_set_tlsext_host_name(ssl, rem_server_ip);
        /* Configure server hostname check */
        if (!SSL_set1_host(ssl, rem_server_ip)) {
            ERR_print_errors_fp(stderr);
            goto exit;
        }

        /* Now do SSL connect with server */
        if (SSL_connect(ssl) == 1) {

            printf("SSL connection to server successful\n\n");

            /* Loop to send input from keyboard */
            while (true) {
                /* Get a line of input */
                memset(buffer, 0, BUFFERSIZE);
                txbuf = fgets(buffer, BUFFERSIZE, stdin);

                /* Exit loop on error */
                if (txbuf == NULL) {
                    break;
                }
                /* Exit loop if just a carriage return */
                if (txbuf[0] == '\n') {
                    break;
                }
                /* Send it to the server */
                if ((result = SSL_write(ssl, txbuf, strlen(txbuf))) <= 0) {
                    printf("Server closed connection\n");
                    ERR_print_errors_fp(stderr);
                    break;
                }

                /* Wait for the echo */
                rxlen = SSL_read(ssl, rxbuf, rxcap);
                if (rxlen <= 0) {
                    printf("Server closed connection\n");
                    ERR_print_errors_fp(stderr);
                    break;
                } else {
                    /* Show it */
                    rxbuf[rxlen] = 0;
                    printf("Received: %s", rxbuf);
                }
            }
            printf("Client exiting...\n");
        } else {

            printf("SSL connection to server failed\n\n");

            ERR_print_errors_fp(stderr);
        }
    
exit:
    /* Close up */
    if (ssl != NULL) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    SSL_CTX_free(ssl_ctx);

    if (client_skt != -1)
        close(client_skt);

    return EXIT_SUCCESS;
}

