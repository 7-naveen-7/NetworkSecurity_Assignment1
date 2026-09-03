#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>

constexpr int PORT = 8080;
constexpr int BUFFER_SIZE = 1024;
constexpr const char* SERVER_IP = "10.0.2.10"; // Adjust to Wadiya's IP

int main() {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[BUFFER_SIZE];

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        std::cerr << "Socket creation error \n";
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) {
        std::cerr << "Invalid address / Address not supported \n";
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        std::cerr << "Connection Failed. Is Wadiya running?\n";
        return -1;
    }

    std::cout << "Connected to Wadiya. You can start typing...\n";

    fd_set readfds;

    while (true) {
        FD_ZERO(&readfds);
        
        // 1. Monitor Standard Input (Keyboard = 0)
        FD_SET(STDIN_FILENO, &readfds);
        
        // 2. Monitor the Server Socket (for incoming messages)
        FD_SET(sock, &readfds);

        // The highest file descriptor is 'sock'
        int activity = select(sock + 1, &readfds, NULL, NULL, NULL);
        if (activity < 0) {
            std::cerr << "Select error" << std::endl;
            break;
        }

        // EVENT A: User typed something on the keyboard
        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            memset(buffer, 0, BUFFER_SIZE);
            int bytes_read = read(STDIN_FILENO, buffer, BUFFER_SIZE);
            if (bytes_read > 0) {
                // Remove trailing newline character so it looks clean
                if (buffer[bytes_read - 1] == '\n') buffer[bytes_read - 1] = '\0';
                
                send(sock, buffer, strlen(buffer), 0);
            }
        }

        // EVENT B: Wadiya sent a message
        if (FD_ISSET(sock, &readfds)) {
            memset(buffer, 0, BUFFER_SIZE);
            int valread = read(sock, buffer, BUFFER_SIZE);
            if (valread == 0) {
                // Server closed the connection
                std::cout << "Server disconnected.\n";
                break;
            } else {
                std::cout << ">> " << buffer << "\n";
            }
        }
    }

    close(sock);
    return 0;
}
