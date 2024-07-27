// Last modified on: 4/27/2021

#ifndef MERMAID_CTX_H
#define MERMAID_CTX_H

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#if !defined(OPENSSL_SYS_WINDOWS)
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#else
#include <winsock.h>
#endif

typedef struct mermaid_config_st {
    char *cert_file;
    char *key_file;
    char *ca_file;
    char *ca_path;
    char *ciphers;
    char *dhparam;
    char *bind_addr;
    char *bind_port;
    char *log_file;
    char *log_level;
    char *log_format;
    char *log_time_format;
    char *pid_file;
    char *user;
    char *group;
    char *chroot;
    char *chdir;
    char *uid;
    char *gid;
    char *daemon;
} MERMAID_CONFIG;

typedef struct mermaid_ctx_st {
    MERMAID_CONFIG *config;
    SSL_CTX *ssl_ctx;

    X509 *cert;
    STACK_OF(X509) *chain;

    EVP_PKEY *key;

    int listen_fd;
    int log_fd;
} MERMAID_CTX;

#endif