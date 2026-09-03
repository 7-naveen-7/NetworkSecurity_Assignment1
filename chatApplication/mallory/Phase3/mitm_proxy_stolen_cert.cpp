#include <iostream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <fstream>
#include <openssl/evp.h>
#include <openssl/pem.h>

constexpr int PROXY_PORT = 9090;

std::string read_file(const std::string& filepath) {
    std::ifstream t(filepath);
    return std::string((std::istreambuf_iterator<char>(t)), std::istreambuf_iterator<char>());
}

std::string b64_encode(const std::string& in) {
    std::string out(4 * ((in.size() + 2) / 3), '\0');
    int len = EVP_EncodeBlock((unsigned char*)out.data(), (const unsigned char*)in.data(), in.size());
    out.resize(len); return out;
}

std::string b64_decode(const std::string& in) {
    int pad = 0;
    if (in.length() > 0 && in[in.length() - 1] == '=') pad++;
    if (in.length() > 1 && in[in.length() - 2] == '=') pad++;
    std::string out(3 * in.length() / 4, '\0');
    int len = EVP_DecodeBlock((unsigned char*)out.data(), (const unsigned char*)in.data(), in.length());
    out.resize(len - pad); return out;
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
    std::cout << "[Mallory] Starting Proxy with Stolen Cert but Fake Key...\n";
    
    std::string real_cert = read_file("server_cert.pem"); // Stolen
    FILE* fake_key_file = fopen("fake_key.pem", "r");     // Mallory's own key
    EVP_PKEY* fake_pkey = PEM_read_PrivateKey(fake_key_file, NULL, NULL, NULL);
    fclose(fake_key_file);

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

    // 1. Send the stolen real certificate (Client will validate this successfully)
    std::cout << "[Mallory] Sending stolen real certificate...\n";
    send_all(victim_sock, real_cert);

    // 2. Receive the Challenge
    std::string challenge_b64 = ""; char c;
    while (read(victim_sock, &c, 1) > 0) {
        if (c == '\n') break;
        challenge_b64 += c;
    }
    std::string challenge = b64_decode(challenge_b64);
    std::cout << "[Mallory] Intercepted Challenge. Attempting to forge signature...\n";

    // 3. Attempt to sign with the WRONG key
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, fake_pkey);
    EVP_DigestSignUpdate(mdctx, challenge.data(), challenge.size());
    size_t sig_len; EVP_DigestSignFinal(mdctx, NULL, &sig_len);
    unsigned char* sig = (unsigned char*)malloc(sig_len);
    EVP_DigestSignFinal(mdctx, sig, &sig_len);
    EVP_MD_CTX_free(mdctx);

    std::string sig_str((char*)sig, sig_len); free(sig);
    send_all(victim_sock, b64_encode(sig_str) + "\n");

    // Wait to see what the client does
    if (read(victim_sock, &c, 1) <= 0) {
        std::cout << "[Mallory] Victim closed the connection! Proof-of-Possession blocked the attack.\n";
    }

    EVP_PKEY_free(fake_pkey); close(victim_sock); close(proxy_sock);
    return 0;
}
