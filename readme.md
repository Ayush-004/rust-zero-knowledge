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