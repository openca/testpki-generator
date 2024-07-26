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

#include "mermaid_server.h"

#define server_port     4433

typedef unsigned char   bool;
#define true            1
#define false           0

/*
 * This flag won't be useful until both accept/read (TCP & SSL) methods
 * can be called with a timeout. TBD.
 */
static volatile bool    server_running = true;

static int create_socket(bool isServer)
{
    int s;
    int optval = 1;
    struct sockaddr_in addr;

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    if (isServer) {
        addr.sin_family = AF_INET;
        addr.sin_port = htons(server_port);
        addr.sin_addr.s_addr = INADDR_ANY;

        /* Reuse the address; good for quick restarts */
        if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval))
                < 0) {
            perror("setsockopt(SO_REUSEADDR) failed");
            exit(EXIT_FAILURE);
        }

        if (bind(s, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
            perror("Unable to bind");
            exit(EXIT_FAILURE);
        }

        if (listen(s, 1) < 0) {
            perror("Unable to listen");
            exit(EXIT_FAILURE);
        }
    }

    return s;
}

static SSL_CTX* create_context(bool isServer)
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    if (isServer)
        method = TLS_server_method();
    else
        method = TLS_client_method();

    ctx = SSL_CTX_new(method);
    if (ctx == NULL) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

static void usage(void) {
    printf("\n\tUSAGE: mermaid-server <config_dir>\n\n");
    exit(EXIT_FAILURE);
}


#define BUFFERSIZE 1024
int main(int argc, char **argv)
{
    SSL_CTX *ssl_ctx = NULL;
    SSL *ssl = NULL;

    int server_skt = -1;
    int client_skt = -1;

    char rxbuf[128];
    size_t rxcap = sizeof(rxbuf);
    int rxlen;

    char *config_dir = NULL;

    struct sockaddr_in addr;
#if defined(OPENSSL_SYS_CYGWIN) || defined(OPENSSL_SYS_WINDOWS)
    int addr_len = sizeof(addr);
#else
    unsigned int addr_len = sizeof(addr);
#endif

#if !defined (OPENSSL_SYS_WINDOWS)
    /* ignore SIGPIPE so that server can continue running when client pipe closes abruptly */
    signal(SIGPIPE, SIG_IGN);
#endif

    /* Splash */
    printf("\nMermaid TLS Echo : Simple Echo Client/Server : %s : %s\n\n",
        __DATE__, __TIME__);

    /* Need to know if client or server */
    if (argc < 2) {
        usage();
        /* NOTREACHED */
    }
    
    /* Get the config dir */
    config_dir = argv[1];
    if (config_dir == NULL) {
        usage();
        /* NOTREACHED */
    }
        printf("We are the server on port: %d\n\n", server_port);

    /* Create context used by both client and server */
    ssl_ctx = create_context(true);
    if (ssl_ctx == NULL) {
        perror("Unable to create SSL context");
        exit(EXIT_FAILURE);
    }

    char chain_filename[512] = { 0x0 };
    sprintf(chain_filename, "%s/chains/server.chain", config_dir);

        /* Set the key and cert */
        if (SSL_CTX_use_certificate_chain_file(ssl_ctx, chain_filename) <= 0) {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }

    char key_filename[512] = { 0x0 };
    sprintf(key_filename, "%s/private/server.private", config_dir);

        if (SSL_CTX_use_PrivateKey_file(ssl_ctx, &key_filename[0], SSL_FILETYPE_ASN1) <= 0) {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }

        /* Create server socket; will bind with server port and listen */
        server_skt = create_socket(true);

        /*
         * Loop to accept clients.
         * Need to implement timeouts on TCP & SSL connect/read functions
         * before we can catch a CTRL-C and kill the server.
         */
        while (server_running) {
            /* Wait for TCP connection from client */
            client_skt = accept(server_skt, (struct sockaddr*) &addr,
                    &addr_len);
            if (client_skt < 0) {
                perror("Unable to accept");
                exit(EXIT_FAILURE);
            }

            printf("Client TCP connection accepted\n");

            /* Create server SSL structure using newly accepted client socket */
            ssl = SSL_new(ssl_ctx);
            if (!SSL_set_fd(ssl, client_skt)) {
                ERR_print_errors_fp(stderr);
                exit(EXIT_FAILURE);
            }

            /* Wait for SSL connection from the client */
            if (SSL_accept(ssl) <= 0) {
                ERR_print_errors_fp(stderr);
                server_running = false;
            } else {

                printf("Client SSL connection accepted\n\n");

                /* Echo loop */
                while (true) {
                    /* Get message from client; will fail if client closes connection */
                    if ((rxlen = SSL_read(ssl, rxbuf, rxcap)) <= 0) {
                        if (rxlen == 0) {
                            printf("Client closed connection\n");
                        } else {
                            printf("SSL_read returned %d\n", rxlen);
                        }
                        ERR_print_errors_fp(stderr);
                        break;
                    }
                    /* Insure null terminated input */
                    rxbuf[rxlen] = 0;
                    /* Look for kill switch */
                    if (strcmp(rxbuf, "kill\n") == 0) {
                        /* Terminate...with extreme prejudice */
                        printf("Server received 'kill' command\n");
                        server_running = false;
                        break;
                    }
                    /* Show received message */
                    printf("Received: %s", rxbuf);
                    /* Echo it back */
                    if (SSL_write(ssl, rxbuf, rxlen) <= 0) {
                        ERR_print_errors_fp(stderr);
                    }
                }
            }
            if (server_running) {
                /* Cleanup for next client */
                SSL_shutdown(ssl);
                SSL_free(ssl);
                close(client_skt);
            }
        }
        printf("Server exiting...\n");
    
    /* Close up */
    if (ssl != NULL) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    SSL_CTX_free(ssl_ctx);

    if (server_skt != -1)
        close(server_skt);

    printf("\nAll Done.\n");

    return EXIT_SUCCESS;
}

