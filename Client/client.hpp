#ifndef TLS_CLIENT_H
#define TLS_CLIENT_H

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

// Constant values for sockets connection
#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8080
#define BUFFER_SIZE 1024

/**
 * @brief Initialize OpenSSL library
 */
void init_openssl();

/**
 * @brief Clean up OpenSSL resources
 */
void cleanup_openssl();

/**
 * @brief Create and configure SSL context for client
 * @return Pointer to SSL_CTX structure
 */
SSL_CTX* create_client_context();

/**
 * @brief Configure client SSL context with certificates and keys
 * @param ctx SSL context to configure
 */
void configure_client_ssl(SSL_CTX* ctx);

/**
 * @brief Establish TCP connection to server
 * @param ip Server IP address
 * @param port Server port number
 * @return Socket file descriptor
 */
int connect_to_server(const char* ip, int port);

/**
 * @brief Main client function that establishes TLS connection and communicates with server
 * @return 0 on success, non-zero on failure
 */
int run_tls_client();

#endif /* TLS_CLIENT_H */