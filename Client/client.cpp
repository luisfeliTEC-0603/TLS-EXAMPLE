#include "client.hpp"

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

SSL_CTX* create_client_context() {
    // SSL_CTX Context is a object central structure that holds configuration, certificates, keys, and settings for TLS/SSL connections
   
   // Selects TLS method to use
    const SSL_METHOD* method = TLS_client_method();
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

void configure_client_ssl(SSL_CTX* ctx) {
    // Loads Client Certificate & Private Key
    if (SSL_CTX_use_certificate_file(ctx, "Certs/client.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "Certs/client.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Client private key doesn't match certificate\n");
        exit(EXIT_FAILURE);
    }

    // Load CA certificate to verify server
    if (!SSL_CTX_load_verify_locations(ctx, "Certs/ca.crt", nullptr)) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Enable server certificate verification
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr); // Must verify server cert
    SSL_CTX_set_verify_depth(ctx, 1); // Only allow 1 level of CA chain
}

int connect_to_server(const char* ip, int port) {
    int sock;
    struct sockaddr_in server_addr;

    // Establishes a TCP (Transmission Control Protocol) connection to the server
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    // Configures Server Address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &server_addr.sin_addr) <= 0) {
        perror("Invalid server IP address");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Connects to server
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Unable to connect to server");
        close(sock);
        exit(EXIT_FAILURE);
    }

    return sock;
}

int main() {
    SSL_CTX* ctx = nullptr;
    SSL* ssl = nullptr;  // SSL Object Hold the data for a TLS/SSL connection
    int server_fd = -1;
    char buffer[BUFFER_SIZE];
    int bytes = 0;

    // Initialization and configuration of SSL Context for client
    init_openssl();
    ctx = create_client_context();
    configure_client_ssl(ctx);

    // Start connection to server
    server_fd = connect_to_server(SERVER_IP, SERVER_PORT);
    printf("Connected to %s:%d\n", SERVER_IP, SERVER_PORT);

    // Inherits the settings of the underlying context ctx
    ssl = SSL_new(ctx);
    // Binds SSL to the socket
    SSL_set_fd(ssl, server_fd);

    // Performs the Handshake 
    if (SSL_connect(ssl) <= 0) {
        fprintf(stderr, "TLS handshake failed\n");
        ERR_print_errors_fp(stderr);
    } else {
        // X509 is a certificate
        X509* server_cert = SSL_get_peer_certificate(ssl); // Retrieves the server’s certificate
        if (server_cert) { 
            // Prints certificate details
            printf("Server certificate:\n");
            char* subject = X509_NAME_oneline(X509_get_subject_name(server_cert), nullptr, 0);
            char* issuer = X509_NAME_oneline(X509_get_issuer_name(server_cert), nullptr, 0);
            printf("-> Subject: %s\n", subject);
            printf("-> Issuer: %s\n", issuer);

            // Free the memory
            OPENSSL_free(subject);
            OPENSSL_free(issuer);
            X509_free(server_cert);
        } else {
            fprintf(stderr, "No server certificate received!\n");
        }

        // === SERVER/CLIENT Secure communication ===
        const char* message = "ClientHello!";

        // Send message
        if (SSL_write(ssl, message, strlen(message)) <= 0) {
            fprintf(stderr, "Failed to write to server\n");
            ERR_print_errors_fp(stderr);
        } else {
            // Reads Server response
            bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
            if (bytes > 0) {
                buffer[bytes] = '\0';
                printf("Received: %s\n", buffer);
            } else {
                fprintf(stderr, "Failed to read from server\n");
                ERR_print_errors_fp(stderr);
            }
        }

        // Shuts down an active TLS/SSL connection
        SSL_shutdown(ssl);
    }

    // Clean up
    if (ssl) SSL_free(ssl);
    if (server_fd != -1) close(server_fd);
    if (ctx) SSL_CTX_free(ctx);
    cleanup_openssl();

    return 0;
}
