#include <iostream>
#include <map>
#include <string>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <fstream>
#include <arpa/inet.h>
#include <sys/select.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

constexpr int PORT = 8080;
constexpr int BUFFER_SIZE = 4096;

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

std::string get_fingerprint(const unsigned char* aes_key) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(aes_key, 32, hash);
    char hex[17];
    for (int i = 0; i < 8; i++) sprintf(hex + (i * 2), "%02x", hash[i]);
    hex[16] = '\0';
    return std::string(hex);
}

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

std::string read_file(const std::string& filepath) {
    std::ifstream t(filepath);
    return std::string((std::istreambuf_iterator<char>(t)), std::istreambuf_iterator<char>());
}

enum class AuthState { WAIT_CHALLENGE, WAIT_DH, ENCRYPTED };

struct ClientSession {
    std::string username = "";
    unsigned char aes_key[32];
    std::string rx_buffer = "";
    AuthState state = AuthState::WAIT_CHALLENGE;
};

int main() {
    std::string server_cert_str = read_file("server_cert.pem");
    if (server_cert_str.empty()) { std::cerr << "Failed to read server_cert.pem\n"; return -1; }

    FILE* key_file = fopen("server_key.pem", "r");
    if (!key_file) { std::cerr << "Failed to open server_key.pem\n"; return -1; }
    EVP_PKEY* server_pkey = PEM_read_PrivateKey(key_file, NULL, NULL, NULL);
    fclose(key_file);
    if (!server_pkey) { std::cerr << "Failed to load private key\n"; return -1; }

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
            send_all(new_socket, server_cert_str);
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

                    if (it->second.state == AuthState::WAIT_CHALLENGE) {
                        std::string challenge = b64_decode(frame);
                        EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
                        EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, server_pkey);
                        EVP_DigestSignUpdate(mdctx, challenge.data(), challenge.size());
                        size_t sig_len;
                        EVP_DigestSignFinal(mdctx, NULL, &sig_len);
                        unsigned char* sig = (unsigned char*)malloc(sig_len);
                        EVP_DigestSignFinal(mdctx, sig, &sig_len);
                        EVP_MD_CTX_free(mdctx);

                        std::string sig_str((char*)sig, sig_len);
                        free(sig);
                        send_all(sd, b64_encode(sig_str) + "\n");
                        it->second.state = AuthState::WAIT_DH;
                    }
                    else if (it->second.state == AuthState::WAIT_DH) {
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
                        BN_mod_exp(shared_secret, client_pub, priv_b, p, ctx);

                        char* pub_b_hex = BN_bn2hex(pub_b);
                        send_all(sd, std::string(pub_b_hex) + "\n");

                        int num_bytes = BN_num_bytes(shared_secret);
                        unsigned char* secret_bytes = new unsigned char[num_bytes];
                        BN_bn2bin(shared_secret, secret_bytes);
                        SHA256(secret_bytes, num_bytes, it->second.aes_key);

                        it->second.state = AuthState::ENCRYPTED;
                        delete[] secret_bytes; OPENSSL_free(pub_b_hex);
                        BN_free(p); BN_free(g); BN_free(priv_b); BN_free(pub_b); BN_free(client_pub); BN_free(shared_secret); BN_CTX_free(ctx);
                    }
                    else if (it->second.state == AuthState::ENCRYPTED) {
                        std::string decrypted_msg;
                        if (aes_decrypt(frame, it->second.aes_key, decrypted_msg)) {
                            if (decrypted_msg.empty()) continue;

                            if (it->second.username.empty()) {
                                it->second.username = decrypted_msg;
                                std::cout << "User registered as: " << it->second.username << "\n";
                                send_all(sd, aes_encrypt("Hello " + decrypted_msg + "! Registration successful.", it->second.aes_key) + "\n");
                            } else {
                                if (decrypted_msg == "/who") {
                                    std::string list = "Online: ";
                                    for (auto const& [_, s] : clients) if (!s.username.empty()) list += s.username + " ";
                                    send_all(sd, aes_encrypt(list, it->second.aes_key) + "\n");
                                } else if (decrypted_msg.rfind("@", 0) == 0) {
                                    size_t sp = decrypted_msg.find(' ');
                                    if (sp != std::string::npos) {
                                        std::string target = decrypted_msg.substr(1, sp - 1);
                                        std::string body = decrypted_msg.substr(sp + 1);
                                        
                                        // ----------------------------------------------------
                                        // Log the routed payload payload
                                        // ----------------------------------------------------
                                        std::cout << "[SERVER LOG] " << it->second.username 
                                                  << " -> " << target << " | Payload: " << body << "\n";
                                        
                                        for (auto const& [dest_sd, s] : clients) {
                                            if (s.username == target) {
                                                std::string fwd = aes_encrypt("[" + it->second.username + "]: " + body, s.aes_key) + "\n";
                                                send_all(dest_sd, fwd);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            ++it;
        }
    }
    close(server_fd);
    EVP_PKEY_free(server_pkey);
    return 0;
}
