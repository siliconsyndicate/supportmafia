# Note: Execute on the respective server
# Note: Replace "entity-server" with the respective server or client name
# Note: Send the generated CSR (*-req.pem) to Entity for signing since Entity is the CA

# Create Certificate Signing Request for Servers and CLients

# Note: Replace with respective file names
KEY="entity-server-key.pem"
CSR="entity-server-req.pem"

# 1. Generate Entity Server's private key and certificate signing request (CSR)
openssl req -newkey rsa:4096 -nodes -sha256 -keyout $KEY -out $CSR -subj "/C=US/ST=Indiana/L=Indiana/O=Leanafy/OU=Tech/CN=leanafywms/emailAddress=tech@leanafy.com"