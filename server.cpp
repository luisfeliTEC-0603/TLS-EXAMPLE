#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

const int PORT = 8080;

int main() {
    // Create socket
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        std::cerr << "Failed to create socket\n";
        return 1;
    }

    // Bind socket to port
    sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (sockaddr*)&address, sizeof(address)) < 0) {
        std::cerr << "Failed to bind\n";
        return 1;
    }

    // Listen for connections
    if (listen(server_fd, 3) < 0) {
        std::cerr << "Failed to listen\n";
        return 1;
    }

    std::cout << "Server listening on port " << PORT << std::endl;

    // Accept a connection
    int addrlen = sizeof(address);
    int client_socket = accept(server_fd, (sockaddr*)&address, (socklen_t*)&addrlen);
    if (client_socket < 0) {
        std::cerr << "Failed to accept connection\n";
        return 1;
    }

    // Read and send messages
    char buffer[1024] = {0};
    int bytes_read = read(client_socket, buffer, 1024);
    std::cout << "Received: " << buffer << std::endl;

    const char* response = "Hello from server!";
    send(client_socket, response, strlen(response), 0);
    std::cout << "Response sent\n";

    // Cleanup
    close(client_socket);
    close(server_fd);
    return 0;
}