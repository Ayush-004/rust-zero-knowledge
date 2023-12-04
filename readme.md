# Zero-Knowledge Proof Authentication System with Rust and gRPC

## Introduction

Welcome to the repository for our Zero-Knowledge Proof (ZKP) gRPC client/server application.

## Key Features
### Zero-Knowledge Proof Protocol:
Employs a cryptographic method where one party (the prover) can prove to another party (the verifier) that they know a value x, without conveying any information apart from the fact that they know the value x.
### gRPC Framework:
Utilizes Google's high-performance, open-source universal RPC framework, for communication between the client and server.
### Rust Implementation:
The entire application is built in Rust, known for its safety and performance.
### Docker Integration:
Simplifies deployment and testing through the use of Docker containers, ensuring consistency across various environments.


## To run locally

You will need to install the rust on your machine and also the `protobuf-compiler`, for Linux:

```bash
sudo apt install protobuf-compiler
```

## Docker

You can run the program with Docker. First build the containers:

```
$ docker-compose build zkpserver
```

Run the container:

```
$ docker-compose run --rm zkpserver
```

In the remote terminal that appears run the server:

```
root@e84736012f9a:/zkp-server# cargo run --bin server --release
```

Open a new terminal on your machine and connect to the container:

```
$ docker container ls
CONTAINER ID   IMAGE                  COMMAND   CREATED          STATUS          PORTS     NAMES
e84736012f9a   zkp-course-zkpserver   "bash"    20 minutes ago   Up 20 minutes             zkp-course_zkpserver_run_b1f3fa2cd94a

$ docker exec -it e84736012f9a /bin/bash
```

Run the client:

```
root@e84736012f9a:/zkp-server# cargo run --bin client --release
```


## Application Architecture
### Server
The server component is responsible for handling authentication requests from the client. It uses Zero-Knowledge Proof techniques to validate the authenticity of the client without needing to know or store sensitive information.

### Client
The client initiates authentication requests to the server. It demonstrates how a user can be authenticated securely without revealing their credentials, utilizing the ZKP protocol.

### gRPC Protocol
gRPC is used for the client-server communication. It offers significant advantages in terms of performance and supports efficient bidirectional streaming.

### Zero-Knowledge Proof Protocol
The ZKP implementation is a key feature of this application. It allows for secure authentication without revealing the actual credentials.

## Future Enhancements
### User Interface: 
Developing a user-friendly interface for the client.
### Extended Protocol Support: 
Implementing additional protocols and methods within the ZKP framework.
### Performance Optimization:
Profiling and optimizing the application for better performance and scalability.

# POPL 
### 1) Problem Statement and POPL Angle

**Original Problem:** The primary challenge addressed by this project is to implement a secure and efficient authentication system using Zero-Knowledge Proofs (ZKP) within a gRPC framework. The need for such a system arises from the growing concerns around privacy and data security in digital communications. Traditional authentication methods often risk exposing sensitive user data.

**POPL Angle:** In the context of Principles of Programming Languages (POPL), this project explores the practical application of theoretical concepts in cryptographic protocols and network communication. POPL principles guide the efficient and secure implementation of these protocols in a programming language (Rust in this case), ensuring correctness, safety, and performance.

**Novelty and Differentiation:** Previous solutions may have addressed secure authentication, but this project uniquely integrates ZKP with gRPC in Rust. The choice of Rust brings in safety and performance benefits due to its system-level control and memory safety guarantees. The integration of ZKP ensures that the authentication process reveals no information other than the fact of authentication itself, enhancing privacy.

### 2) Software Architecture

**Architecture Overview:**
- The system follows a **client-server model**.
- **Client Component:** Initiates authentication requests using ZKP.
- **Server Component:** Validates these requests, again leveraging ZKP.
- **Communication Protocol:** gRPC, chosen for its efficiency and support for multiple language implementations.

**Components Developed vs. Reused:**
- **Developed:**
    - ZKP implementation in Rust.
    - Integration of ZKP with the gRPC framework.
- **Reused:**
    - gRPC framework.
    - Rust cryptographic libraries.

**Testing Component:**
- Testing is both local (unit tests in Rust) and remote (testing client-server interactions over gRPC).
- No database involved; the focus is on stateless authentication.

### 3) POPL Aspects

**POPL Concepts in Implementation:**
1. **Type Safety and Memory Management:** Rust’s ownership model ensures safe memory management without a garbage collector, crucial for cryptographic applications where data leaks are a risk.
2. **Concurrent Programming:** Rust's concurrency model is used to handle multiple client requests efficiently and safely.
3. **Functional Programming Features:** Rust's iterators, closures, and pattern matching are used to implement complex logic succinctly and clearly.
4. **Modular Programming:** The application is structured into modules for ZKP, gRPC client, and server, showcasing principles of modular design.
5. **Error Handling:** Rust’s 'Result' and 'Option' types are used for robust error handling without exceptions, ensuring reliability.

**Challenges Faced:**
- Integrating Rust with gRPC was initially challenging due to differing paradigms.
- Ensuring thread safety during concurrent access to shared resources was complex but essential.

### 4) Potential for Future Work

**With More Time:**
- We would explore integrating advanced cryptographic protocols like multi-party computation.
- Enhance the system to support scalable and distributed architectures.

**Additional POPL Aspects:**
- Investigating formal verification of Rust code for cryptographic guarantees.
- Exploring domain-specific languages (DSLs) for defining and implementing cryptographic protocols more intuitively.

This project stands as a testament to the practical application of POPL principles in solving real-world problems in the domain of secure communication and authentication.