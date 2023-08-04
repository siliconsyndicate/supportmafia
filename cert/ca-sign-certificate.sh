# Note: Only execute this on Entity
# Note: Send the generated certificate to the respective service

# Sign Certificate Signing Requests (CSR)

# Note: Replace with respective file names for server and client
CSR="entity-server-req.pem"
CERT="entity-server-cert.pem"

# 1. Use CA's private key to sign Service CSR and get back the signed certificate
openssl x509 -req -in $CSR -days 60 -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out $CERT -extfile ext.cnf

echo "Signed certificate"
openssl x509 -in $CERT -noout -text