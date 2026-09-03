#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <map>
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

struct E2ESession {
    bool established = false;
    BIGNUM* priv_key = nullptr; // Held temporarily during handshake
    unsigned char aes_key[32];
};

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
    // Certificate Validation & Proof of Possession
    // ---------------------------------------------------------
    std::string cert_data = "";
    char c;
    const std::string cert_end_marker = "-----END CERTIFICATE-----\n";
    while (read(sock, &c, 1) > 0) {
        cert_data += c;
        if (cert_data.length() >= cert_end_marker.length() && 
            cert_data.substr(cert_data.length() - cert_end_marker.length()) == cert_end_marker) {
            break;
        }
    }

    BIO* bio = BIO_new_mem_buf(cert_data.data(), cert_data.size());
    X509* server_cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!server_cert) { std::cerr << "Cert parse failed.\n"; return -1; }

    X509_STORE* store = X509_STORE_new();
    X509_STORE_load_locations(store, CA_CERT_PATH, NULL);
    X509_STORE_CTX* vrfy_ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(vrfy_ctx, store, server_cert, NULL);
    if (X509_verify_cert(vrfy_ctx) != 1) { std::cerr << "Cert Validation Failed.\n"; return -1; }
    X509_STORE_CTX_free(vrfy_ctx);
    X509_STORE_free(store);

    X509_NAME* subj = X509_get_subject_name(server_cert);
    char cn_buf[256];
    X509_NAME_get_text_by_NID(subj, NID_commonName, cn_buf, sizeof(cn_buf));
    if (std::string(cn_buf) != SERVER_IP) { std::cerr << "CN mismatch.\n"; return -1; }

    unsigned char challenge[32];
    RAND_bytes(challenge, sizeof(challenge));
    std::string challenge_str((char*)challenge, sizeof(challenge));
    send_all(sock, b64_encode(challenge_str) + "\n");
    
    std::string sig_b64 = "";
    while (read(sock, &c, 1) > 0) {
        if (c == '\n') break;
        sig_b64 += c;
    }
    std::string sig_raw = b64_decode(sig_b64);

    EVP_PKEY* server_pubkey = X509_get_pubkey(server_cert);
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, server_pubkey);
    EVP_DigestVerifyUpdate(mdctx, challenge, sizeof(challenge));
    if (EVP_DigestVerifyFinal(mdctx, (const unsigned char*)sig_raw.data(), sig_raw.size()) != 1) {
        std::cerr << "Proof of Possession Failed.\n"; return -1;
    }
    EVP_MD_CTX_free(mdctx); EVP_PKEY_free(server_pubkey); X509_free(server_cert);

    // ---------------------------------------------------------
    // Diffie-Hellman Client-Server Setup
    // ---------------------------------------------------------
    BN_CTX* bn_ctx = BN_CTX_new();
    BIGNUM* p = NULL; BIGNUM* g = NULL;
    BIGNUM* priv_a = BN_new(); BIGNUM* pub_a = BN_new();
    BN_hex2bn(&p, MODP_3072_PRIME); BN_hex2bn(&g, "2");
    
    BN_rand_range(priv_a, p);
    BN_mod_exp(pub_a, g, priv_a, p, bn_ctx);

    char* pub_a_hex = BN_bn2hex(pub_a);
    send_all(sock, std::string(pub_a_hex) + "\n");

    std::string server_pub_hex = "";
    while (read(sock, &c, 1) > 0) {
        if (c == '\n') break;
        server_pub_hex += c;
    }

    BIGNUM* server_pub = NULL; BIGNUM* shared_secret = BN_new();
    BN_hex2bn(&server_pub, server_pub_hex.c_str());
    BN_mod_exp(shared_secret, server_pub, priv_a, p, bn_ctx);

    unsigned char client_server_aes_key[32];
    int num_bytes = BN_num_bytes(shared_secret);
    unsigned char* secret_bytes = new unsigned char[num_bytes];
    BN_bn2bin(shared_secret, secret_bytes);
    SHA256(secret_bytes, num_bytes, client_server_aes_key);

    delete[] secret_bytes; OPENSSL_free(pub_a_hex);
    BN_free(p); BN_free(g); BN_free(priv_a); BN_free(pub_a); BN_free(server_pub); BN_free(shared_secret); BN_CTX_free(bn_ctx);

    std::cout << "[+] Server DH Exchange Complete.\n";
    std::cout << "Please enter your username to register: " << std::flush;

    // ---------------------------------------------------------
    // Event Loop 
    // ---------------------------------------------------------
    fd_set readfds;
    std::string rx_buffer = "";
    char temp_buf[BUFFER_SIZE];

    bool registered = false;
    std::string active_partner = "";
    std::map<std::string, E2ESession> e2e_sessions; // Keeps track of peers

    while (true) {
        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);
        FD_SET(sock, &readfds);

        if (select(sock + 1, &readfds, NULL, NULL, NULL) < 0) break;

        // EVENT A: USER TYPING
        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            memset(temp_buf, 0, BUFFER_SIZE);
            int b_read = read(STDIN_FILENO, temp_buf, BUFFER_SIZE);
            if (b_read > 0) {
                if (temp_buf[b_read - 1] == '\n') temp_buf[b_read - 1] = '\0';
                std::string input(temp_buf);
                if (input.empty()) continue;

                if (!registered) {
                    send_all(sock, aes_encrypt(input, client_server_aes_key) + "\n");
                    registered = true;
                } else {
                    std::string to_send = "";

                    // Phase 4: Init E2E command
                    if (input.rfind("/e2e ", 0) == 0) {
                        active_partner = input.substr(5);
                        
                        // Generate E2E DH Keys
                        BN_CTX* ctx = BN_CTX_new();
                        BIGNUM* modp = NULL; BIGNUM* gen = NULL;
                        BN_hex2bn(&modp, MODP_3072_PRIME); BN_hex2bn(&gen, "2");

                        BIGNUM* e2e_priv = BN_new();
                        BIGNUM* e2e_pub = BN_new();
                        BN_rand_range(e2e_priv, modp);
                        BN_mod_exp(e2e_pub, gen, e2e_priv, modp, ctx);

                        // Save private key for when ACK comes back
                        if (e2e_sessions[active_partner].priv_key) BN_free(e2e_sessions[active_partner].priv_key);
                        e2e_sessions[active_partner].priv_key = e2e_priv; 
                        e2e_sessions[active_partner].established = false;

                        char* e2e_pub_hex = BN_bn2hex(e2e_pub);
                        to_send = "@" + active_partner + " __E2E_INIT__ " + e2e_pub_hex;

                        std::cout << "[*] Sending E2E Handshake Initialization to " << active_partner << "...\n";

                        OPENSSL_free(e2e_pub_hex); BN_free(modp); BN_free(gen); BN_free(e2e_pub); BN_CTX_free(ctx);
                    } 
                    else if (input.rfind("/chat ", 0) == 0) {
                        active_partner = input.substr(6);
                        std::cout << "[Local] Active chat partner set to: " << active_partner << "\n";
                        continue;
                    } 
                    else if (input == "/quit") {
                        break;
                    } 
                    else if (input == "/who") {
                        to_send = input;
                    } 
                    else if (input.rfind("@", 0) == 0) {
                        to_send = input; // Raw override
                    } 
                    else {
                        if (active_partner.empty()) {
                            std::cout << "[Local] No active partner. Use /chat <username> or /e2e <username> first.\n";
                            continue;
                        }

                        // Double Encryption for Phase 4: Encrypt payload first with E2E key if established
                        if (e2e_sessions[active_partner].established) {
                            std::string e2e_cipher = aes_encrypt(input, e2e_sessions[active_partner].aes_key);
                            to_send = "@" + active_partner + " __E2E_MSG__ " + e2e_cipher;
                        } else {
                            to_send = "@" + active_partner + " " + input;
                        }
                    }

                    // Wrap everything in Client-Server Encryption
                    if (!to_send.empty()) {
                        send_all(sock, aes_encrypt(to_send, client_server_aes_key) + "\n");
                    }
                }
            }
        }

        // EVENT B: SERVER MESSAGE RECEIVED
        if (FD_ISSET(sock, &readfds)) {
            int valread = read(sock, temp_buf, BUFFER_SIZE - 1);
            if (valread <= 0) {
                std::cout << "\nServer disconnected.\n"; break;
            }
            rx_buffer.append(temp_buf, valread);

            size_t pos;
            while ((pos = rx_buffer.find('\n')) != std::string::npos) {
                std::string frame = rx_buffer.substr(0, pos);
                rx_buffer.erase(0, pos + 1);

                std::string decrypted;
                if (aes_decrypt(frame, client_server_aes_key, decrypted)) {
                    
                    //Parse "[SenderName]: payload" format
                    if (decrypted.rfind("[", 0) == 0) {
                        size_t end_bracket = decrypted.find("]: ");
                        if (end_bracket != std::string::npos) {
                            std::string sender = decrypted.substr(1, end_bracket - 1);
                            std::string body = decrypted.substr(end_bracket + 3);

                            // INTERCEPT: Target initiated an E2E exchange
                            if (body.rfind("__E2E_INIT__ ", 0) == 0) {
                                std::string peer_pub_hex = body.substr(13);
                                
                                BN_CTX* ctx = BN_CTX_new();
                                BIGNUM* modp = NULL; BIGNUM* gen = NULL;
                                BN_hex2bn(&modp, MODP_3072_PRIME); BN_hex2bn(&gen, "2");

                                BIGNUM* peer_pub = NULL;
                                BN_hex2bn(&peer_pub, peer_pub_hex.c_str());

                                BIGNUM* e2e_priv = BN_new(); BIGNUM* e2e_pub = BN_new();
                                BN_rand_range(e2e_priv, modp);
                                BN_mod_exp(e2e_pub, gen, e2e_priv, modp, ctx);

                                BIGNUM* shared_secret = BN_new();
                                BN_mod_exp(shared_secret, peer_pub, e2e_priv, modp, ctx);

                                int n_bytes = BN_num_bytes(shared_secret);
                                unsigned char* s_bytes = new unsigned char[n_bytes];
                                BN_bn2bin(shared_secret, s_bytes);
                                SHA256(s_bytes, n_bytes, e2e_sessions[sender].aes_key);
                                e2e_sessions[sender].established = true;

                                // Send ACK back to initiator
                                char* e2e_pub_hex = BN_bn2hex(e2e_pub);
                                std::string ack_msg = "@" + sender + " __E2E_ACK__ " + e2e_pub_hex;
                                send_all(sock, aes_encrypt(ack_msg, client_server_aes_key) + "\n");

                                std::cout << "[*] End-to-End Session Established with " << sender << " (Responder)\n";
                                std::cout << "[*] Fingerprint: " << get_fingerprint(e2e_sessions[sender].aes_key) << "\n";

                                delete[] s_bytes; OPENSSL_free(e2e_pub_hex);
                                BN_free(modp); BN_free(gen); BN_free(peer_pub); BN_free(e2e_priv); BN_free(e2e_pub); BN_free(shared_secret); BN_CTX_free(ctx);
                            }
                            // INTERCEPT: Target acknowledged our E2E request
                            else if (body.rfind("__E2E_ACK__ ", 0) == 0) {
                                std::string peer_pub_hex = body.substr(12);

                                BN_CTX* ctx = BN_CTX_new();
                                BIGNUM* modp = NULL; 
                                BN_hex2bn(&modp, MODP_3072_PRIME);

                                BIGNUM* peer_pub = NULL;
                                BN_hex2bn(&peer_pub, peer_pub_hex.c_str());

                                BIGNUM* shared_secret = BN_new();
                                BN_mod_exp(shared_secret, peer_pub, e2e_sessions[sender].priv_key, modp, ctx);

                                int n_bytes = BN_num_bytes(shared_secret);
                                unsigned char* s_bytes = new unsigned char[n_bytes];
                                BN_bn2bin(shared_secret, s_bytes);
                                SHA256(s_bytes, n_bytes, e2e_sessions[sender].aes_key);
                                
                                e2e_sessions[sender].established = true;
                                BN_free(e2e_sessions[sender].priv_key);
                                e2e_sessions[sender].priv_key = nullptr; // Clean up

                                std::cout << "[*] End-to-End Session Established with " << sender << " (Initiator)\n";
                                std::cout << "[*] Fingerprint: " << get_fingerprint(e2e_sessions[sender].aes_key) << "\n";

                                delete[] s_bytes; BN_free(modp); BN_free(peer_pub); BN_free(shared_secret); BN_CTX_free(ctx);
                            }
                            // INTERCEPT: Double-encrypted E2E Message
                            else if (body.rfind("__E2E_MSG__ ", 0) == 0) {
                                std::string b64_cipher = body.substr(12);
                                std::string plaintext;
                                if (e2e_sessions[sender].established && aes_decrypt(b64_cipher, e2e_sessions[sender].aes_key, plaintext)) {
                                    std::cout << "[" << sender << "] (E2E): " << plaintext << "\n";
                                } else {
                                    std::cout << "[ERROR] Failed to decrypt E2E message from " << sender << ". Key mismatch.\n";
                                }
                            }
                            // Regular Unencrypted (but client-server encrypted) message
                            else {
                                std::cout << "[" << sender << "]: " << body << "\n";
                            }
                        } else {
                            std::cout << ">> " << decrypted << "\n"; // E.g., Registration ACK or /who response
                        }
                    } else {
                        std::cout << ">> " << decrypted << "\n";
                    }
                } else {
                    std::cout << "[ERROR] Server-link tampering detected!\n";
                }
            }
        }
    }
    close(sock);
    return 0;
}
