#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

const int PORT = 8080;
const char* SERVER_IP = "127.0.0.1";

int main() {
    // Create socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        std::cerr << "Failed to create socket\n";
        return 1;
    }

    // Connect to server
    sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr);

    if (connect(sock, (sockaddr*)&serv_addr, sizeof(serv_addr))) {
        std::cerr << "Connection failed\n";
        return 1;
    }

    // Send and receive messages
    const char* message = "Hello from client!";
    send(sock, message, strlen(message), 0);
    std::cout << "Message sent\n";

    char buffer[1024] = {0};
    int bytes_read = read(sock, buffer, 1024);
    std::cout << "Server response: " << buffer << std::endl;

    // Cleanup
    close(sock);
    return 0;
}