#!/bin/bash

# Enable strict error handling - script will exit immediately if any command fails
set -e

# =============================================
# Configuration
# =============================================

# Server Common Name - must match the hostname used in TLS connections
# 'localhost' local development
SERVER_CN="localhost"

# Client Common Name - identifier for client certificate authentication
CLIENT_CN="client"

# Certificate validity period
VALID_DAYS=1

# Output directory where all certificates will be stored
OUTPUT_DIR="Certs"

# =============================================
# Directory Setup
# =============================================

# Create the output directory if it doesn't exist
# -p flag prevents errors if directory already exists
mkdir -p "$OUTPUT_DIR"

# =============================================
# Certificate Authority (Root CA) Generation
# =============================================

echo "\n-> Generating CA (ca.key, ca.crt)..."

# Generate self-signed root CA certificate and private key
# -x509: Output a self-signed certificate
# -newkey rsa:2048: Create new RSA 2048-bit key pair
# -nodes: Do not encrypt the private key
# -keyout: Save private key to file
# -out: Save certificate to file
# -days: Validity period in days
# -subj: Set certificate subject (only CN needed for CA)
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$OUTPUT_DIR/ca.key" -out "$OUTPUT_DIR/ca.crt" \
    -days "$VALID_DAYS" -subj "/CN=My Root CA"

# =============================================
# Server Certificate Generation
# =============================================

echo "\n-> Generating Server certificate..."

# Generate server private key and Certificate Signing Request (CSR)
# -newkey: Create new key pair while generating CSR
# -keyout: Save server private key
# -out: Save CSR file
openssl req -newkey rsa:2048 -nodes -keyout "$OUTPUT_DIR/server.key" -out "$OUTPUT_DIR/server.csr" \
    -subj "/CN=$SERVER_CN"

# Sign the server CSR with the root CA to create final certificate
# -req: Input is a CSR file
# -in: Server CSR to sign
# -CA: CA certificate file
# -CAkey: CA private key file
# -CAcreateserial: Create serial number file if it doesn't exist
# -out: Output signed certificate
openssl x509 -req -in "$OUTPUT_DIR/server.csr" -CA "$OUTPUT_DIR/ca.crt" -CAkey "$OUTPUT_DIR/ca.key" \
    -CAcreateserial -out "$OUTPUT_DIR/server.crt" -days "$VALID_DAYS"

# =============================================
# Client Certificate Generation
# =============================================

echo "\n-> Generating Client certificate..."

# Generate client private key and CSR
# Same options as server certificate but with client CN
openssl req -newkey rsa:2048 -nodes -keyout "$OUTPUT_DIR/client.key" -out "$OUTPUT_DIR/client.csr" \
    -subj "/CN=$CLIENT_CN"

# Sign client CSR with root CA
# -CAserial: Use existing serial number file created for server cert
openssl x509 -req -in "$OUTPUT_DIR/client.csr" -CA "$OUTPUT_DIR/ca.crt" -CAkey "$OUTPUT_DIR/ca.key" \
    -CAserial "$OUTPUT_DIR/ca.srl" -out "$OUTPUT_DIR/client.crt" -days "$VALID_DAYS"

# =============================================
# Final Output
# =============================================

# Display summary of generated files
echo -e "\n-> Certificates generated in '$OUTPUT_DIR':"
ls -l "$OUTPUT_DIR"