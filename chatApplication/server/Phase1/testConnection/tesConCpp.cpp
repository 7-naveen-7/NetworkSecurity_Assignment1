#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <arpa/inet.h>

constexpr int PORT = 8080;
constexpr int BUFFER_SIZE = 1024;

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen;
    char buffer[BUFFER_SIZE] = {0};

    // 1. Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        std::cerr << "Socket failed" << std::endl;
        exit(EXIT_FAILURE);
    }

    // 2. Set socket options (to reuse port)
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        std::cerr << "setsockopt failed" << std::endl;
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY; // Listen on all interfaces
    address.sin_port = htons(PORT);

    // 3. Bind the socket to the IP and Port
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        std::cerr << "Bind failed" << std::endl;
        exit(EXIT_FAILURE);
    }

    // 4. Listen for incoming connections
    if (listen(server_fd, 3) < 0) {
        std::cerr << "Listen failed" << std::endl;
        exit(EXIT_FAILURE);
    }

    std::cout << "Wadiya Server is listening on port " << PORT << "..." << std::endl;

    addrlen = sizeof(address);
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
        std::cerr << "Accept failed" << std::endl;
        exit(EXIT_FAILURE);
    }

    std::cout << "Connection established with a client!" << std::endl;

    // 5. Receive the message
    int valread = read(new_socket, buffer, BUFFER_SIZE);
    if (valread > 0) {
        std::cout << "Message received from client: " << buffer << std::endl;
    }

    // 6. Send a response back
    const char *msg = "Message received by Wadiya Server!";
    send(new_socket, msg, strlen(msg), 0);
    std::cout << "Response sent to client." << std::endl;

    close(new_socket);
    close(server_fd);
    return 0;
}
