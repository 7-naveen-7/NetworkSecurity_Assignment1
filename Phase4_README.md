# Phase 4

In this Phase, We have added an additional functionality of End-to-end encryption between clients.

## Pre-requisites to run

Copy all the clients and server of previous Phase except client.cpp and server.cpp respectively.

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

Run the following to invoke End-to-End encryption Between clients on client interface 

```/e2e username```

After running this command on both clients, end to end communication is established and communication can be done.
