# Phase 5

In this Phase, Forward Secrecy is added to our application along with renegotiation.

## Pre-requisites to run

Copy all the clients and server of previous Phase except client.cpp and server.cpp respectively.

*1. Basic Implementation*

### On Server
```text
$cd Assignment1/server/Phase3/
$g++ -std=c++17 server.cpp -o server -lssl -lcrypto #Ignore if ran already
$./server
```
### On Clients
```text
$cd Assignment1/client/Phase3/
$scp wadiya@10.0.2.10:~/Assignment1/Phase3/server_cert.pem
$g++ -std=c++17 client.cpp -o client -lssl -lcrypto #Ignore if ran already
$./client
```
