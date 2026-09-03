# Phase 1

## Description
Phase 1 implements a centralized, unencrypted TCP chat application across distributed virtual machines. It is developed in three stages: a basic 1-on-1 connection test (`testConnection`), a continuous multi-client broadcast server using I/O multiplexing (`contConnectionTest`), and the final command-routing protocol supporting direct messaging and user management (`finalCode`).

## Directory Structure
```text
Assignment1/
├── client/
│   └── Phase1/
│       ├── testConnection/
│       ├── contConnectionTest/
│       └── finalCode/
│   └── Phase2/
│   └── Phase3/
│   └── Phase4/
│   └── Phase5/
└── server/
    └── Phase1/
        ├── testConnection/
        ├── contConnectionTest/
        └── finalCode/
    └── Phase2/
    └── Phase3/
    └── Phase4/
    └── Phase5/
```

## Exection Instructions

*1. Basic Connection*

### On Server
```text
$cd Assignment1/server/Phase1/testConnection
$g++ server.cpp -o server
$./server
```
### On Client
```text
$cd Assignment1/client/Phase1/testConnection
$g++ client.cpp -o client
$./client
```
*2. Continuous Connection*

### On Server
```text
$cd Assignment1/server/Phase1/contConnectionTest
$g++ server.cpp -o server
$./server
```
### On Client
```text
$cd Assignment1/client/Phase1/contConnectionTest
$g++ client.cpp -o client
$./client
```
*3. Final Implementation*

### On Server
```text
$cd Assignment1/server/Phase1/finalCode
$g++ server.cpp -o server
$./server
```
### On Client
```text
$cd Assignment1/client/Phase1/finalCode
$g++ client.cpp -o client
$./client
```
## Commands
| Command             | Behaviour                                             |
|---------------------|-------------------------------------------------------|
| `@username message` | Send `message` to `username` and select them.         |
| `/chat username`    | Switch selected partner (no message sent).            |
| `/who`              | List online users.                                    |
| `/quit`             | Disconnect and exit.                                  |

## VM topology (test environment)
| VM      | IP             | Role      |Default Gateway   |
|---------|----------------|-----------|------------------|
| wadiya  | 10.0.2.10  | Server/S   | 10.0.2.10 |
| aladeen    | 10.0.2.20  | Client/C1 | 10.0.2.10 |
| nadal  | 10.0.2.30   | Client/C2 | 10.0.2.10 |
| tamir | 10.0.2.40 | Mallory/Eve | - |

tamir VM is setup for further Phases
