#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>

constexpr int PORT = 8080;
constexpr int BUFFER_SIZE = 1024;
constexpr const char* SERVER_IP = "10.0.2.10";

int main() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        std::cerr << "Connection Failed.\n";
        return -1;
    }

    fd_set readfds;
    char buffer[BUFFER_SIZE];
    
    bool registered = false;
    std::string active_partner = "";
    std::string rx_buffer = ""; // For receiving framed messages

    while (true) {
        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);
        FD_SET(sock, &readfds);

        if (select(sock + 1, &readfds, NULL, NULL, NULL) < 0) break;

        // EVENT A: User typed on keyboard
        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            memset(buffer, 0, BUFFER_SIZE);
            int bytes_read = read(STDIN_FILENO, buffer, BUFFER_SIZE);
            if (bytes_read > 0) {
                if (buffer[bytes_read - 1] == '\n') buffer[bytes_read - 1] = '\0';
                std::string input(buffer);
                std::string to_send = "";

                if (!registered) {
                    to_send = input + "\n"; // Append frame delimiter
                    registered = true;
                } else {
                    if (input.rfind("@", 0) == 0) {
                        size_t space_pos = input.find(' ');
                        if (space_pos != std::string::npos) {
                            active_partner = input.substr(1, space_pos - 1);
                            to_send = input + "\n";
                        } else std::cout << "[Local] Use @username message\n";
                    } 
                    else if (input.rfind("/chat ", 0) == 0) {
                        active_partner = input.substr(6);
                        std::cout << "[Local] Active chat partner set to: " << active_partner << "\n";
                    } 
                    else if (input == "/who" || input.rfind("/e2e ", 0) == 0) {
                        to_send = input + "\n";
                    } 
                    else if (input == "/quit") {
                        std::cout << "[Local] Disconnecting...\n";
                        break; 
                    } 
                    else { 
                        if (active_partner.empty()) {
                            std::cout << "[Local] No active partner. Use /chat <username> first.\n";
                        } else {
                            to_send = "@" + active_partner + " " + input + "\n";
                        }
                    }
                }
                if (!to_send.empty()) {
                    send(sock, to_send.c_str(), to_send.length(), 0);
                }
            }
        }

        // EVENT B: Incoming message from Server
        if (FD_ISSET(sock, &readfds)) {
            memset(buffer, 0, BUFFER_SIZE);
            int valread = read(sock, buffer, BUFFER_SIZE - 1);
            if (valread <= 0) {
                std::cout << "\nServer disconnected.\n";
                break;
            } else {
                buffer[valread] = '\0';
                rx_buffer += buffer;
                size_t pos;
                // Process full frames only
                while ((pos = rx_buffer.find('\n')) != std::string::npos) {
                    std::string msg = rx_buffer.substr(0, pos);
                    rx_buffer.erase(0, pos + 1);
                    std::cout << ">> " << msg << "\n";
                }
            }
        }
    }
    close(sock);
    return 0;
}
