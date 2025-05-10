#include "server.hpp"

int init_socket(int port) {
    int server_socket;
    struct sockaddr_in address;

    // Configure address structure
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = INADDR_ANY;

    // Create TCP socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    // Set SO_REUSEADDR to prevent "address already in use" errors
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    // Bind socket to address
    if (bind(server_socket, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("Unable to bind");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    // Start listening (backlog of 10 connections)
    if (listen(server_socket, 10) < 0) {
        perror("Unable to listen");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    return server_socket;
}

void init_openssl() {
    // Loads human-readable error messages for debugging
    SSL_load_error_strings();
    // Registers available SSL/TLS methods
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    // Releases OpenSSL resources to prevent memory leaks
    EVP_cleanup();
}

SSL_CTX* create_context() {
    // SSL_CTX Context is a object central structure that holds configuration, certificates, keys, and settings for TLS/SSL connections
   
   // Selects TLS method to use
   const SSL_METHOD* method = TLS_server_method();
   // Create the context based on the method
   SSL_CTX* ctx = SSL_CTX_new(method);
   if (!ctx) { // Exists if the context creation fails
       ERR_print_errors_fp(stderr);
       exit(EXIT_FAILURE);
   }

   // Enforce TLS 1.2+ only
   SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
   SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

   return ctx;
}

void configure_context(SSL_CTX* ctx) {
    // Load server certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, "Certs/server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "Certs/server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Verify private key matches certificate
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match certificate\n");
        exit(EXIT_FAILURE);
    }

    // Load CA certificate for client verification
    if (SSL_CTX_load_verify_locations(ctx, "Certs/ca.crt", NULL) != 1) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Require client certificate verification
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_verify_depth(ctx, 1);
}

int main() {
    int sock;
    SSL_CTX* ctx;

    // Disable stdout buffering for real-time logging
    setvbuf(stdout, NULL, _IONBF, 0);

    // Initialize OpenSSL
    init_openssl();
    ctx = create_context();
    configure_context(ctx);

    // Create listening socket
    sock = init_socket(SERVER_PORT);
    printf("Server listening on port 8080...\n");

    // Main server loop
    while (1) {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL* ssl;

        // Accept new connection
        int client = accept(sock, (struct sockaddr*)&addr, &len);
        if (client < 0) {
            perror("Unable to accept connection");
            continue;  // Continue instead of exiting to keep server running
        }

        // Get client IP for logging
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr.sin_addr, client_ip, sizeof(client_ip));
        printf("Connection from %s:%d\n", client_ip, ntohs(addr.sin_port));

        // Create new SSL connection
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);

        // Perform SSL handshake
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(client);
            continue;
        }

        // Verify client certificate
        X509* client_cert = SSL_get_peer_certificate(ssl);
        if (client_cert) {
            char* subject = X509_NAME_oneline(X509_get_subject_name(client_cert), 0, 0);
            printf("Client certificate: %s\n", subject);
            OPENSSL_free(subject);
            X509_free(client_cert);
        } else {
            printf("No client certificate provided!\n");
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(client);
            continue;
        }

        // Read data from client
        char buffer[BUFFER_SIZE];
        int bytes = SSL_read(ssl, buffer, sizeof(buffer));
        if (bytes > 0) {
            buffer[bytes] = '\0';
            printf("Received: %s\n", buffer);

            // Send response
            const char* response = "ServerHello!";
            SSL_write(ssl, response, strlen(response));
        }

        // Clean up
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client);
    }

    // Cleanup
    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();

    return 0;
}