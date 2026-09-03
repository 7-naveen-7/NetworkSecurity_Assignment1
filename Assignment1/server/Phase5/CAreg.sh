# 1. Create the CA (on the server for convenience)
openssl req -x509 -newkey rsa:4096 -keyout ca_key.pem -out ca_cert.pem \
    -sha256 -days 3650 -nodes -subj "/CN=MyChatCA"

# 2. Generate Server Key and CSR
openssl genrsa -out server_key.pem 4096
openssl req -new -key server_key.pem -out server.csr -subj "/CN=10.0.2.10"

# 3. Sign the Server Certificate using your CA
openssl x509 -req -in server.csr -CA ca_cert.pem -CAkey ca_key.pem \
    -CAcreateserial -out server_cert.pem -days 365 -sha256
