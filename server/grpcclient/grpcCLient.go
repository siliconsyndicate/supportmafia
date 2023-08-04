package grpcclient

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"supportmafia/app"
	"supportmafia/server/config"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// Used for Staging. Load client's credentials for Server Side TLS connection
func LoadStagingClientTLSCredentials() (credentials.TransportCredentials, error) {
	// Load certificate of the CA who signed server's and client's certificate
	ServerCA, err := ioutil.ReadFile("cert/ca-cert.pem")
	if err != nil {
		return nil, err
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(ServerCA) {
		return nil, fmt.Errorf("failed to add server CA's certificate")
	}

	// Create the credentials and return it
	config := &tls.Config{
		RootCAs: certPool,
	}

	return credentials.NewTLS(config), nil
}

// Used for Production. Load client's credentials for Mutual TLS connection
func LoadProdClientTLSCredentials() (credentials.TransportCredentials, error) {
	// Load certificate of the CA who signed server's and client's certificate
	ServerCA, err := ioutil.ReadFile("cert/ca-cert.pem")
	if err != nil {
		return nil, err
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(ServerCA) {
		return nil, fmt.Errorf("failed to add server CA's certificate")
	}

	// Load client's certificate and private key
	// Replace with service specific client
	clientCert, err := tls.LoadX509KeyPair("cert/entity-client-cert.pem", "cert/entity-client-key.pem")
	if err != nil {
		return nil, err
	}

	// Create the credentials and return it
	config := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      certPool,
	}

	return credentials.NewTLS(config), nil
}

// Load Credentials based on Environment
func LoadGrpcClientCredentials(env string) grpc.DialOption {
	var tlsCreds credentials.TransportCredentials
	var err error

	if env == "production" {
		tlsCreds, err = LoadProdClientTLSCredentials()
		if err != nil {
			log.Fatalf("failed to load prod grpc server credentials: %v", err)
		}

	} else if env == "staging" {
		tlsCreds, err = LoadStagingClientTLSCredentials()
		if err != nil {
			log.Fatalf("failed to load staging grpc credentials: %v", err)
		}

	} else {
		tlsCreds = insecure.NewCredentials()
	}

	return grpc.WithTransportCredentials(tlsCreds)
}

// Create GRPC Clients here
// Don't forget to add Conn.Close() for that Client in Server's StopServer() method
func NewGrpcClient(c *config.Config) *app.GrpcClient {
	// Same creds can be used for all clients
	// creds := LoadGrpcClientCredentials(c.ServerConfig.GrpcEnv)

	// // Core client
	// coreConn, err := grpc.Dial(c.GrpcAddr.Core, creds)
	// if err != nil {
	// 	log.Fatalf("did not connect: %v", err)
	// }
	// coreClient := core_proto.NewCoreClient(coreConn)
	// core := &app.Core{
	// 	Client: coreClient,
	// 	Conn:   coreConn,
	// }

	// Another client like above

	// Add all clients in this struct
	grpcClient := &app.GrpcClient{
		// Add new clients here
		//Core: core,
	}

	return grpcClient
}
