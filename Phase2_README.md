# Phase 2 README

## Description

Phase 2 implements provides encryption over previous phase using Diffie-Hillman key exchange that utilizes RFC 3526 MODP group 14 (3072 bit prime number) and AES GCM encryption scheme. Each client performs an independent DH key exchange with the server. Added a code tamper_client to explain the scenario of what happens when a byte of a captured ciphertext is modified and allowed to process. Added MiTM codes in Mallory machine Tamir titled mitm_proxy which does mitm attack  

## Prerequisites to Run for enabling openssl libraries - 
```text
sudo apt install libssl-dev
```

## Execution Instructions

*1. Basic Implementation*

### On Server
```text
cd Assignment1/server/Phase2/
g++ -std=c++17 server.cpp -o server -lssl -lcrypto #Ignore if ran already
./server
```
### On Clients
```text
cd Assignment1/client/Phase2/
g++ -std=c++17 client.cpp -o client -lssl -lcrypto #Ignore if ran already
./client
```

*2. To Prove that AES-GCM detects tampering*
 
### On Server
```text
./server
```
### On one of the Client
```text
$g++ -std=c++17 tamper_client.cpp -o tamper_client -lssl -lcrypto #Ignore if ran already
$./tamper_client
#Keep Chatting and run below
$/tamper
#Next message which is sent by the other client will be blocked.
```
### On the other Client
```text
$./client
```

*3. To Perform MiTM*
 
### On Server Wadiya
```text
$./server
```
### On Clients
```text
$g++ -std=c++17 vuln_client.cpp -o vuln_client -lssl -lcrypto #Ignore if ran already
$./vuln_client
```
### On Mallory Tamir
```text
$g++ -std=c++17 mitm_proxy.cpp -o mitm_proxy -lssl -lcrypto
```
