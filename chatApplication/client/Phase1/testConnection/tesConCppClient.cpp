#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <arpa/inet.h>

constexpr int PORT = 8080;
constexpr int BUFFER_SIZE = 1024;
constexpr const char* SERVER_IP = "10.0.2.10"; 

int main() {
    int sock = 0;
    struct sockaddr_in serv_addr;
    const char *message = "Hello Wadiya! This is a message from a client.";
    char buffer[BUFFER_SIZE] = {0};

    // 1. Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        std::cerr << "\n Socket creation error \n" << std::endl;
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // 2. Convert IPv4 address from text to binary (Target: Wadiya's IP)
    if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) {
        std::cerr << "\nInvalid address / Address not supported \n" << std::endl;
        return -1;
    }

    // 3. Connect to the server
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        std::cerr << "\nConnection Failed. Is the server running?\n" << std::endl;
        return -1;
    }

    // 4. Send message
    send(sock, message, strlen(message), 0);
    std::cout << "Message sent to server: " << message << std::endl;

    // 5. Receive response
    int valread = read(sock, buffer, BUFFER_SIZE);
    if (valread > 0) {
        std::cout << "Server response: " << buffer << std::endl;
    }

    close(sock);
    return 0;
}
