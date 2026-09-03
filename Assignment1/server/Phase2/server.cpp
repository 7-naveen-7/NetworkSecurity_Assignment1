#include <iostream>
#include <map>
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

constexpr int PORT = 8080;
constexpr int BUFFER_SIZE = 4096;

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

// Base64 Helpers to prevent \n collisions in binary ciphertext
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

// Generates a hash-based fingerprint for verification (Req 3.2)
std::string get_fingerprint(const unsigned char* aes_key) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(aes_key, 32, hash);
    char hex[17];
    for (int i = 0; i < 8; i++) sprintf(hex + (i * 2), "%02x", hash[i]);
    hex[16] = '\0';
    return std::string(hex);
}

// AES-256-GCM Encryption (Returns Base64 String)
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

// AES-256-GCM Decryption (Accepts Base64 String)
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

struct ClientSession {
    std::string username = "";
    unsigned char aes_key[32];
    std::string rx_buffer = "";
    bool dh_completed = false;
};

int main() {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));

    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    bind(server_fd, (struct sockaddr*)&address, sizeof(address));
    listen(server_fd, 5);
    std::cout << "Secure Server listening on port " << PORT << "...\n";

    std::map<int, ClientSession> clients;
    fd_set readfds;
    char buffer[BUFFER_SIZE];

    while (true) {
        FD_ZERO(&readfds);
        FD_SET(server_fd, &readfds);
        int max_sd = server_fd;

        for (auto const& [sd, session] : clients) {
            FD_SET(sd, &readfds);
            if (sd > max_sd) max_sd = sd;
        }

        if (select(max_sd + 1, &readfds, NULL, NULL, NULL) < 0) continue;

        if (FD_ISSET(server_fd, &readfds)) {
            int new_socket = accept(server_fd, NULL, NULL);
            clients[new_socket] = ClientSession();
            std::cout << "New connection. Awaiting DH Key...\n";
        }

        for (auto it = clients.begin(); it != clients.end();) {
            int sd = it->first;
            if (FD_ISSET(sd, &readfds)) {
                memset(buffer, 0, BUFFER_SIZE);
                int valread = read(sd, buffer, BUFFER_SIZE - 1);

                if (valread <= 0) {
                    std::cout << "Client disconnected.\n";
                    close(sd);
                    it = clients.erase(it);
                    continue;
                }

                it->second.rx_buffer.append(buffer, valread);
                size_t pos;

                while ((pos = it->second.rx_buffer.find('\n')) != std::string::npos) {
                    std::string frame = it->second.rx_buffer.substr(0, pos);
                    it->second.rx_buffer.erase(0, pos + 1);

                    // 1. Diffie-Hellman Handshake Phase
                    if (!it->second.dh_completed) {
                        BN_CTX* ctx = BN_CTX_new();
                        BIGNUM* p = NULL; BIGNUM* g = NULL;
                        BIGNUM* priv_b = BN_new();
                        BIGNUM* pub_b = BN_new();
                        BIGNUM* client_pub = NULL;
                        BIGNUM* shared_secret = BN_new();

                        BN_hex2bn(&p, MODP_3072_PRIME);
                        BN_hex2bn(&g, "2");
                        BN_hex2bn(&client_pub, frame.c_str());

                        BN_rand_range(priv_b, p);
                        BN_mod_exp(pub_b, g, priv_b, p, ctx);
                        BN_mod_exp(shared_secret, client_pub, priv_b, p, ctx); // S = A^b mod p

                        char* pub_b_hex = BN_bn2hex(pub_b);
                        std::string server_pub_msg = std::string(pub_b_hex) + "\n";
                        if (!send_all(sd, server_pub_msg)) {
                            std::cout << "[Session " << sd << "] Failed to send DH public value.\n";
                        }

                        int num_bytes = BN_num_bytes(shared_secret);
                        unsigned char* secret_bytes = new unsigned char[num_bytes];
                        BN_bn2bin(shared_secret, secret_bytes);
                        SHA256(secret_bytes, num_bytes, it->second.aes_key); // Key Derivation

                        it->second.dh_completed = true;
                        std::cout << "[Session " << sd << "] DH Exchange Complete. Fingerprint: " << get_fingerprint(it->second.aes_key) << "\n";

                        delete[] secret_bytes;
                        OPENSSL_free(pub_b_hex);
                        BN_free(p); BN_free(g); BN_free(priv_b); BN_free(pub_b); BN_free(client_pub); BN_free(shared_secret); BN_CTX_free(ctx);
                    }
                    // 2. Encrypted Communication Phase
                    else {
                        std::string decrypted_msg;
                        if (aes_decrypt(frame, it->second.aes_key, decrypted_msg)) {
                            // Trim and ignore empty inputs
                            if (decrypted_msg.empty()) continue;

                            // Registration
                            if (it->second.username.empty()) {
                                it->second.username = decrypted_msg;
                                std::cout << "User registered as: " << it->second.username << "\n";
                                std::string ack = aes_encrypt("Hello " + decrypted_msg + "! Registration successful.", it->second.aes_key) + "\n";
                                send_all(sd, ack);
                            }
                            // Routing
                            else {
                                if (decrypted_msg == "/who") {
                                    std::string list = "Online: ";
                                    for (auto const& [_, s] : clients) if (!s.username.empty()) list += s.username + " ";
                                    std::string resp = aes_encrypt(list, it->second.aes_key) + "\n";
                                    send_all(sd, resp);
                                } else if (decrypted_msg.rfind("@", 0) == 0) {
                                    size_t sp = decrypted_msg.find(' ');
                                    if (sp != std::string::npos) {
                                        std::string target = decrypted_msg.substr(1, sp - 1);
                                        std::string body = decrypted_msg.substr(sp + 1);
                                        for (auto const& [dest_sd, s] : clients) {
                                            if (s.username == target) {
                                                std::string fwd = aes_encrypt("[" + it->second.username + "]: " + body, s.aes_key) + "\n";
                                                send_all(dest_sd, fwd);
                                            }
                                        }
                                    }
                                }
                            }
                        } else {
                            std::cout << "[WARNING] AES-GCM Authentication Failed! Packet Tampering Detected.\n";
                        }
                    }
                }
            }
            ++it;
        }
    }
    close(server_fd);
    return 0;
}
