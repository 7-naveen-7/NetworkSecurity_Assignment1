#include <iostream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <fstream>

constexpr int PROXY_PORT = 9090;

std::string read_file(const std::string& filepath) {
    std::ifstream t(filepath);
    return std::string((std::istreambuf_iterator<char>(t)), std::istreambuf_iterator<char>());
}

bool send_all(int sock, const std::string& data) {
    size_t total_sent = 0;
    while (total_sent < data.size()) {
        ssize_t n = send(sock, data.data() + total_sent, data.size() - total_sent, 0);
        if (n <= 0) return false;
        total_sent += (size_t)n;
    }
    return true;
}

int main() {
    std::cout << "[Mallory] Starting Proxy with Untrusted Certificate...\n";
    
    // Mallory loads her own fake/self-signed certificate
    std::string fake_cert = read_file("fake_cert.pem");
    if(fake_cert.empty()) { std::cerr << "Missing fake_cert.pem\n"; return -1; }

    int proxy_sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in proxy_addr;
    memset(&proxy_addr, 0, sizeof(proxy_addr));
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_port = htons(PROXY_PORT);
    proxy_addr.sin_addr.s_addr = INADDR_ANY;

    int opt = 1; setsockopt(proxy_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    bind(proxy_sock, (struct sockaddr*)&proxy_addr, sizeof(proxy_addr));
    listen(proxy_sock, 5);

    struct sockaddr_in cli_addr; socklen_t cli_len = sizeof(cli_addr);
    int victim_sock = accept(proxy_sock, (struct sockaddr*)&cli_addr, &cli_len);
    std::cout << "[Mallory] Victim connected. Sending fake certificate...\n";

    // Send the fake certificate to the client
    send_all(victim_sock, fake_cert);

    // Wait to see what the client does
    char c;
    if (read(victim_sock, &c, 1) <= 0) {
        std::cout << "[Mallory] Victim closed the connection! Attack failed.\n";
    }

    close(victim_sock);
    close(proxy_sock);
    return 0;
}
