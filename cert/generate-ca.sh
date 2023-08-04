# Note: Only execute this on Entity
# Generate CA's Private Key and Self Signed Certificate

# 1. Generate CA's private key and self-signed certificate
openssl req -x509 -nodes -sha256 -newkey rsa:4096 -days 365 -keyout ca-key.pem -out ca-cert.pem -subj "/C=US/ST=Indiana/L=Indiana/O=Leanafy/OU=Tech/CN=leanafywms/emailAddress=tech@leanafy.com"

echo "CA's self-signed certificate"
openssl x509 -in ca-cert.pem -noout -text