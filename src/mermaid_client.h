
// Last modified on: 4/27/2021

#ifndef MERMAID_CLIENT_H
#define MERMAID_CLIENT_H

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

#include "mermaid_ctx.h"

#endif