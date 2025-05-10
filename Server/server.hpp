#ifndef TLS_SERVER_H
#define TLS_SERVER_H

// Standard Input/Output library
#include <stdio.h>
// Access to POSIX operating system APIs like 'close()' for closing socket file descriptors
#include <unistd.h>
// String handling functions
#include <string.h>

// Core socket functions
#include <sys/socket.h>
// Internet operations 
#include <arpa/inet.h>

// OpenSSL SSL/TLS functions and error handling
#include <openssl/ssl.h>
#include <openssl/err.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8080
#define BUFFER_SIZE 1024

/**
 * @brief Initializes and returns a TCP socket bound to specified port
 * @param port The port number to bind the socket to
 * @return Socket file descriptor on success
 */
int init_socket(int port);

/**
 * @brief Initialize OpenSSL library
 */
void init_openssl();

/**
 * @brief Clean up OpenSSL resources
 */
void cleanup_openssl();

/**
 * @brief Configures SSL context with certificates and security settings
 * @param ctx Pointer to SSL_CTX structure to be configured
 * @note Requires valid certificate and key files to be present
 */
void configure_context(SSL_CTX *ctx);

#endif /* TLS_SERVER_H */