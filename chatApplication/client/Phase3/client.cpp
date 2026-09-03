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
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

constexpr int PORT = 8080;
constexpr int BUFFER_SIZE = 4096;
constexpr const char* SERVER_IP = "10.0.2.10";
constexpr const char* CA_CERT_PATH = "ca_cert.pem";

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

int main() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        std::cerr << "Connection Failed.\n";
        return -1;
    }
    std::cout << "Connected to Server. Validating Certificate...\n";

    // ---------------------------------------------------------
    // PHASE 3: Certificate Reception & Validation
    // ---------------------------------------------------------
    std::string cert_data = "";
    char c;
    const std::string cert_end_marker = "-----END CERTIFICATE-----\n";
    while (read(sock, &c, 1) > 0) {
        cert_data += c;
        if (cert_data.length() >= cert_end_marker.length()) {
            if (cert_data.substr(cert_data.length() - cert_end_marker.length()) == cert_end_marker) {
                break;
            }
        }
    }

    // Load received cert into X509 structure
    BIO* bio = BIO_new_mem_buf(cert_data.data(), cert_data.size());
    X509* server_cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!server_cert) {
        std::cerr << "[!] CRITICAL: Failed to parse server certificate. Aborting.\n";
        close(sock); return -1;
    }

    // Step A & B: Validate Signature and Validity Period using X509_STORE
    X509_STORE* store = X509_STORE_new();
    if (X509_STORE_load_locations(store, CA_CERT_PATH, NULL) != 1) {
        std::cerr << "[!] CRITICAL: Failed to load Trusted CA root certificate. Aborting.\n";
        close(sock); return -1;
    }

    X509_STORE_CTX* vrfy_ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(vrfy_ctx, store, server_cert, NULL);
    int verify_result = X509_verify_cert(vrfy_ctx);
    X509_STORE_CTX_free(vrfy_ctx);
    X509_STORE_free(store);

    if (verify_result != 1) {
        std::cerr << "[!] CRITICAL: Certificate Validation Failed! (Untrusted CA or Expired). Aborting.\n";
        close(sock); return -1;
    }

    // Step C: Validate Common Name (CN) matches EXPECTED Server IP
    X509_NAME* subj = X509_get_subject_name(server_cert);
    char cn_buf[256];
    X509_NAME_get_text_by_NID(subj, NID_commonName, cn_buf, sizeof(cn_buf));
    if (std::string(cn_buf) != SERVER_IP) {
        std::cerr << "[!] CRITICAL: Certificate CN mismatch! Expected: " << SERVER_IP << ", Found: " << cn_buf << ". Aborting.\n";
        close(sock); return -1;
    }

    std::cout << "[+] Certificate Validated Successfully (CA, Dates, Identity Verified).\n";

    // ---------------------------------------------------------
    // PHASE 3: Proof of Possession (Challenge-Response)
    // ---------------------------------------------------------
    unsigned char challenge[32];
    RAND_bytes(challenge, sizeof(challenge));
    std::string challenge_str((char*)challenge, sizeof(challenge));
    
    // Send challenge to server
    send_all(sock, b64_encode(challenge_str) + "\n");
    std::cout << "[*] Sent Cryptographic Challenge to verify Server possesses Private Key...\n";

    // Read the signature back
    std::string sig_b64 = "";
    while (read(sock, &c, 1) > 0) {
        if (c == '\n') break;
        sig_b64 += c;
    }
    std::string sig_raw = b64_decode(sig_b64);

    // Verify signature using the Public Key in the validated certificate
    EVP_PKEY* server_pubkey = X509_get_pubkey(server_cert);
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, server_pubkey);
    EVP_DigestVerifyUpdate(mdctx, challenge, sizeof(challenge));
    int sig_valid = EVP_DigestVerifyFinal(mdctx, (const unsigned char*)sig_raw.data(), sig_raw.size());
    
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(server_pubkey);
    X509_free(server_cert);

    if (sig_valid != 1) {
        std::cerr << "[!] CRITICAL: Proof of Possession Failed! Server doesn't hold the private key. Aborting.\n";
        close(sock); return -1;
    }
    
    std::cout << "[+] Proof of Possession Confirmed. Initiating Diffie-Hellman Exchange...\n";

    // ---------------------------------------------------------
    // Legacy Phase 2: Diffie-Hellman & Chat Loop
    // ---------------------------------------------------------
    BN_CTX* bn_ctx = BN_CTX_new();
    BIGNUM* p = NULL; BIGNUM* g = NULL;
    BIGNUM* priv_a = BN_new();
    BIGNUM* pub_a = BN_new();

    BN_hex2bn(&p, MODP_3072_PRIME);
    BN_hex2bn(&g, "2");
    BN_rand_range(priv_a, p);
    BN_mod_exp(pub_a, g, priv_a, p, bn_ctx);

    char* pub_a_hex = BN_bn2hex(pub_a);
    std::string init_msg = std::string(pub_a_hex) + "\n";
    if (!send_all(sock, init_msg)) {
        std::cerr << "Failed to send DH public value.\n";
        return -1;
    }

    std::string server_pub_hex = "";
    while (read(sock, &c, 1) > 0) {
        if (c == '\n') break;
        server_pub_hex += c;
    }

    BIGNUM* server_pub = NULL;
    BIGNUM* shared_secret = BN_new();
    BN_hex2bn(&server_pub, server_pub_hex.c_str());
    BN_mod_exp(shared_secret, server_pub, priv_a, p, bn_ctx);

    unsigned char aes_key[32];
    int num_bytes = BN_num_bytes(shared_secret);
    unsigned char* secret_bytes = new unsigned char[num_bytes];
    BN_bn2bin(shared_secret, secret_bytes);
    SHA256(secret_bytes, num_bytes, aes_key);

    delete[] secret_bytes;
    OPENSSL_free(pub_a_hex);
    BN_free(p); BN_free(g); BN_free(priv_a); BN_free(pub_a); BN_free(server_pub); BN_free(shared_secret); BN_CTX_free(bn_ctx);

    std::cout << "DH Key Exchange Complete. Fingerprint: " << get_fingerprint(aes_key) << "\n";
    std::cout << "Secure Channel Established via AES-256-GCM.\n";
    std::cout << "Please enter your username to register: " << std::flush;

    fd_set readfds;
    std::string rx_buffer = "";
    char temp_buf[BUFFER_SIZE];

    bool registered = false;
    std::string active_partner = "";

    while (true) {
        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);
        FD_SET(sock, &readfds);

        if (select(sock + 1, &readfds, NULL, NULL, NULL) < 0) break;

        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            memset(temp_buf, 0, BUFFER_SIZE);
            int b_read = read(STDIN_FILENO, temp_buf, BUFFER_SIZE);
            if (b_read > 0) {
                if (temp_buf[b_read - 1] == '\n') temp_buf[b_read - 1] = '\0';
                std::string input(temp_buf);

                if (input.empty()) continue;

                if (!registered) {
                    std::string encrypted = aes_encrypt(input, aes_key) + "\n";
                    if (!send_all(sock, encrypted)) { std::cerr << "Send failed.\n"; break; }
                    registered = true;
                } else {
                    std::string to_send = "";

                    if (input.rfind("/chat ", 0) == 0) {
                        active_partner = input.substr(6);
                        std::cout << "[Local] Active chat partner set to: " << active_partner << "\n";
                        continue;
                    } else if (input == "/quit") {
                        break;
                    } else if (input == "/who" || input.rfind("@", 0) == 0) {
                        to_send = input;
                    } else {
                        if (active_partner.empty()) {
                            std::cout << "[Local] No active partner. Use /chat <username> first.\n";
                            continue;
                        } else {
                            to_send = "@" + active_partner + " " + input;
                        }
                    }

                    if (!to_send.empty()) {
                        std::string encrypted = aes_encrypt(to_send, aes_key) + "\n";
                        if (!send_all(sock, encrypted)) { std::cerr << "Send failed.\n"; break; }
                    }
                }
            }
        }

        if (FD_ISSET(sock, &readfds)) {
            int valread = read(sock, temp_buf, BUFFER_SIZE - 1);
            if (valread <= 0) {
                std::cout << "\nServer disconnected.\n";
                break;
            }
            rx_buffer.append(temp_buf, valread);

            size_t pos;
            while ((pos = rx_buffer.find('\n')) != std::string::npos) {
                std::string frame = rx_buffer.substr(0, pos);
                rx_buffer.erase(0, pos + 1);

                std::string decrypted;
                if (aes_decrypt(frame, aes_key, decrypted)) {
                    std::cout << ">> " << decrypted << "\n";
                } else {
                    std::cout << "[ERROR] Message decryption/authentication failed! Tampering detected.\n";
                }
            }
        }
    }
    close(sock);
    return 0;
}
