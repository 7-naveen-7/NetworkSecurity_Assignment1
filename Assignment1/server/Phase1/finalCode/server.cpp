#include <iostream>
#include <map>
#include <string>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>

constexpr int PORT = 8080;
constexpr int BUFFER_SIZE = 1024;

int main() {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address;
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    bind(server_fd, (struct sockaddr *)&address, sizeof(address));
    listen(server_fd, 5);
    std::cout << "Wadiya Server listening on port " << PORT << "...\n";
    std::cout << "Type '/quit' at any time to gracefully shut down the server.\n";

    std::map<int, std::string> clients;        
    std::map<int, std::string> client_buffers; 
    fd_set readfds;
    char buffer[BUFFER_SIZE];
    bool server_running = true;

    while (server_running) {
        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds); // 1. Monitor Server Keyboard
        FD_SET(server_fd, &readfds);    // 2. Monitor Listening Socket
        int max_sd = server_fd;

        for (auto const& [sd, username] : clients) {
            FD_SET(sd, &readfds);
            if (sd > max_sd) max_sd = sd;
        }

        if (select(max_sd + 1, &readfds, NULL, NULL, NULL) < 0) continue;

        // EVENT A: Server Administrator Keyboard Input
        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            memset(buffer, 0, BUFFER_SIZE);
            int bytes_read = read(STDIN_FILENO, buffer, BUFFER_SIZE);
            if (bytes_read > 0) {
                if (buffer[bytes_read - 1] == '\n') buffer[bytes_read - 1] = '\0';
                std::string input(buffer);
                
                if (input == "/quit") {
                    std::cout << "[Server] Initiating graceful shutdown...\n";
                    server_running = false; // Break the while loop
                    continue; 
                } else {
                    std::cout << "[Server] Unknown command. Type /quit to exit.\n";
                }
            }
        }

        // EVENT B: New Connection
        if (FD_ISSET(server_fd, &readfds)) {
            int new_socket = accept(server_fd, NULL, NULL);
            clients[new_socket] = ""; 
            client_buffers[new_socket] = "";
            const char* welcome = "Welcome! Please enter your username (no spaces):\n";
            send(new_socket, welcome, strlen(welcome), 0);
        }

        // EVENT C: Incoming Client Data (Framing Logic remains exactly the same)
        for (auto it = clients.begin(); it != clients.end(); ) {
            int sd = it->first;
            
            if (FD_ISSET(sd, &readfds)) {
                memset(buffer, 0, BUFFER_SIZE);
                int valread = read(sd, buffer, BUFFER_SIZE - 1); 
                
                if (valread <= 0) { 
                    std::cout << (it->second.empty() ? "Unknown" : it->second) << " disconnected.\n";
                    close(sd);
                    client_buffers.erase(sd);
                    it = clients.erase(it);
                    continue; 
                } 
                
                buffer[valread] = '\0';
                client_buffers[sd] += buffer; 
                
                size_t pos;
                while ((pos = client_buffers[sd].find('\n')) != std::string::npos) {
                    std::string msg = client_buffers[sd].substr(0, pos); 
                    client_buffers[sd].erase(0, pos + 1);                
                    if (!msg.empty() && msg.back() == '\r') msg.pop_back();

                    std::string sender = it->second.empty() ? "Unregistered" : it->second;
                    std::cout << "[AUDIT LOG] Relaying plaintext from " << sender << ": " << msg << "\n";

                    if (it->second == "") {
                        if (msg.find(' ') != std::string::npos) {
                            std::string err = "[Server] Error: Usernames cannot contain spaces. Try again:\n";
                            send(sd, err.c_str(), err.length(), 0);
                        } else {
                            it->second = msg;
                            std::string ack = "Hello " + msg + "! Use /who to see online users.\n";
                            send(sd, ack.c_str(), ack.length(), 0);
                        }
                    } else {
                        if (msg == "/who") {
                            std::string who_list = "[Server] Online users: ";
                            for (auto const& [d_sd, d_name] : clients) {
                                if (!d_name.empty()) who_list += d_name + ", ";
                            }
                            who_list += "\n";
                            send(sd, who_list.c_str(), who_list.length(), 0);
                        } 
                        else if (msg.rfind("@", 0) == 0) {
                            size_t space_pos = msg.find(' ');
                            if (space_pos != std::string::npos) {
                                std::string target = msg.substr(1, space_pos - 1);
                                std::string actual_msg = msg.substr(space_pos + 1);
                                
                                bool found = false;
                                for (auto const& [dest_sd, dest_name] : clients) {
                                    if (dest_name == target) {
                                        std::string f_msg = "[" + sender + "]: " + actual_msg + "\n";
                                        send(dest_sd, f_msg.c_str(), f_msg.length(), 0);
                                        found = true;
                                        break;
                                    }
                                }
                                if (!found) {
                                    std::string err = "[Server] User '" + target + "' offline.\n";
                                    send(sd, err.c_str(), err.length(), 0);
                                }
                            }
                        }
                    }
                }
            }
            ++it; 
        }
    }

    // --- GRACEFUL SHUTDOWN SEQUENCE ---
    std::cout << "Disconnecting all active clients...\n";
    for (auto const& [sd, username] : clients) {
        std::string quit_msg = "[Server] Server is shutting down. Goodbye!\n";
        send(sd, quit_msg.c_str(), quit_msg.length(), 0);
        close(sd);
    }
    
    close(server_fd);
    std::cout << "Wadiya Server successfully terminated.\n";
    return 0;
}
