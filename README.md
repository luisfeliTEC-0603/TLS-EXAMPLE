# Simple TLS Example

## Overview
This project demonstrates the implementation of mutual TLS (mTLS) authentication for secure socket communication between a client and server in C++ using OpenSSL. The solution includes:
- A self-signed Certificate Authority (CA)
- Server and client certificate generation
- TLS-secured socket communication
- Two-way authentication (mTLS)

## Dependencies
- C++17 compatible compiler (GCC 9+ or Clang 10+)
- OpenSSL 1.1.1 or newer
- Make Utility

n Debian-based systems, the necessary tools can be installed with the following command:
```bash
sudo apt update
sudo apt install -y build-essential libssl-dev make
```

## How to Use
First the necessary certificates have to be generated, this can be achieve by running the following commands:   
```bash
chmod +x generate_certs.sh
./generate_certs.sh
```
After that, the project has to be build, a `Makefile` was added for this purpose. To compile the files run:
```bash
make
``` 
Once the files were complied the server and client can be use with:
```bash
./server
./client # in another terminal
```
By default the code will use the port `8080`.

## Troubleshooting
### Port Conflicts
If the server port is occupied after the operation, run the next commands to kill the previous process:
```bash
sudo lsof -i : <PORT>
kill -9 <PROCESS-ID>
```
### Build Errors
- **OpenSSL not found:** Reinstall OpenSSL development packages
- **Permission denied:** Run `chmod +x generate_certs.sh` to grand execute permissions. 

## Expected Output
Only after the credentials are validated with the `TLS` protocol, server and client are going to exchange greetings.

## Considerations
The generated certificates are for development only. As they lack a proper level of security, e.g. the current script doesn't currently password-protect private keys nor does it encrypts them.

## References 
 OpenSSL Documentation : https://docs.openssl.org/1.0.2/man3/

