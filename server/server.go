/*
	The server package binds all the struct and interfaces of various aspects such as router, database, logging etc.
	StartServer and StopServer functions are exposed to call them via main package or via command line to start/stop
	the execution.

	The server itself listing on some address and port (localhost:8000 (default)) via go routine and will be blocked until
	StopServer function is called via some function or command line. Before stoping server all the resources and connections are closed.
*/

package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"supportmafia/api"
	"supportmafia/app"
	"supportmafia/server/auth"
	"supportmafia/server/config"
	goKafka "supportmafia/server/kafka"
	"supportmafia/server/logger"
	"supportmafia/server/middleware"
	"supportmafia/server/storage"
	elastic "supportmafia/server/storage/elasticsearch"
	memorystorage "supportmafia/server/storage/memory"
	mongostorage "supportmafia/server/storage/mongodb"
	redisstorage "supportmafia/server/storage/redis"
	"supportmafia/server/validator"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/google"
	"github.com/rs/cors"
	"github.com/rs/zerolog"
	"github.com/urfave/negroni"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	grpcClient "supportmafia/server/grpcclient"
)

// Server object encapsulates api, business logic (app),router, storage layer and loggers
type Server struct {
	httpServer *http.Server
	Router     *mux.Router
	Log        *zerolog.Logger
	Config     *config.Config
	Kafka      goKafka.Kafka
	MongoDB    storage.DB
	Redis      storage.Redis

	API *api.API
}

// NewServer returns a new Server object
func NewServer() *Server {
	c := config.GetConfig()
	ms := mongostorage.NewMongoStorage(&c.DatabaseConfig)
	redis := redisstorage.NewRedisStorage(&c.RedisConfig)
	es := elastic.NewESConnection(&c.ESConfig)

	r := mux.NewRouter()

	server := &Server{
		httpServer: &http.Server{},
		Config:     c,
		MongoDB:    ms,
		Router:     r,
	}

	server.InitLoggers()

	if c.ServerConfig.UseMemoryStore {
		server.Redis = memorystorage.NewMemoryStorage()
	} else {
		server.Redis = redis
	}
	sessionAuth := auth.NewSessionAuth(&auth.SessionAuthOpts{Config: &c.SessionConfig, Client: server.Redis})

	// Initializing api endpoints and controller
	apiLogger := server.Log.With().Str("type", "api").Logger()
	appLogger := server.Log.With().Str("type", "app").Logger()

	server.API = api.NewAPI(&api.Options{
		MainRouter:  r,
		Logger:      &apiLogger,
		Config:      &c.APIConfig,
		TokenAuth:   auth.NewTokenAuthentication(&c.TokenAuthConfig, sessionAuth),
		SessionAuth: sessionAuth,
		Validator:   validator.NewValidation(),
	})

	// Register GRPC clients
	gc := grpcClient.NewGrpcClient(c)

	// Initializing app and services
	server.API.App = app.NewApp(&app.Options{SessionAuth: sessionAuth, MongoDB: ms, Redis: redis, ES: es, Logger: &appLogger, Config: &c.APPConfig, GrpcClient: gc})
	// server.API.App.Example = app.InitExample(&app.ExampleOpts{DBName: "example", MongoStorage: ms, Logger: server.Log})
	app.InitService(server.API.App)
	app.InitProducer(server.API.App)
	app.InitConsumer(server.API.App)

	return server
}

// StartServer function initialize middlewares, router, loggers, and server config. It establishes connection with database & other services.
// After setting up the server it runs the server on specified address and port.
func (s *Server) StartServer() {

	// Goth
	key := "secret_key"  // Replace with your SESSION_SECRET or similar
	maxAge := 86400 * 30 // 30 days
	isProd := false      // Set to true when serving over https

	store := sessions.NewCookieStore([]byte(key))
	store.MaxAge(maxAge)
	store.Options.Path = "/"
	store.Options.HttpOnly = true // HttpOnly should always be enabled
	store.Options.Secure = isProd

	gothic.Store = store
	goth.UseProviders(
		google.New(s.API.Config.GoogleOAuth.ClientID, s.API.Config.GoogleOAuth.ClientSecret, "https://48a4-114-143-3-90.ngrok-free.app/auth/google/callback", "email", "profile"),
	)
	n := negroni.New()
	c := cors.New(cors.Options{
		AllowedOrigins:   s.Config.CORSConfig.AllowedOrigins,
		AllowedMethods:   s.Config.CORSConfig.AllowedMethods,
		AllowCredentials: s.Config.CORSConfig.AllowCredentials,
		AllowedHeaders:   s.Config.CORSConfig.AllowedHeaders,
	})
	n.Use(c)

	if s.Config.MiddlewareConfig.EnableRequestLog {
		requestLogger := s.Log.With().Str("type", "request").Logger()
		n.UseFunc(middleware.NewRequestLoggerMiddleware(&requestLogger).GetMiddlewareHandler())
	}
	n.UseFunc(middleware.NewAuthenticationMiddleware(s.API.SessionAuth).GetMiddlewareHandler())

	n.UseHandler(s.Router)

	s.httpServer = &http.Server{
		Handler:      n,
		Addr:         fmt.Sprintf("%s:%s", s.Config.ServerConfig.ListenAddr, s.Config.ServerConfig.Port),
		ReadTimeout:  s.Config.ServerConfig.ReadTimeout * time.Second,
		WriteTimeout: s.Config.ServerConfig.WriteTimeout * time.Second,
	}

	s.Log.Info().Msgf("Staring server at %s:%s", s.Config.ServerConfig.ListenAddr, s.Config.ServerConfig.Port)
	go func() {
		err := s.httpServer.ListenAndServe()
		if err != nil {
			s.Log.Error().Err(err).Msg("")
			return
		}
	}()

	// GRPC server implementation
	go func(*Server) {
		listenAt := fmt.Sprintf("%s:%s", s.Config.ServerConfig.ListenAddr, s.Config.ServerConfig.GrpcPort)
		lis, err := net.Listen("tcp", listenAt)
		if err != nil {
			s.Log.Error().Err(err).Msg("could not start grpc port")
			return
		}

		gs := grpc.NewServer(LoadGrpcServerCredentials(s.Config.ServerConfig.GrpcEnv))
		// grpcApp := &app.Grpc{
		// 	App: s.API.App,
		// 	DB:  s.API.App.MongoDB.Client.Database(s.Config.APPConfig.UserConfig.DBName),
		// 	ES:  s.API.App.ES.Conn(),
		// }

		// Replace with specific server proto
		//entity_proto.RegisterEntityServer(gs, grpcApp)

		s.Log.Info().Msgf("Starting gRPC server at %s:%s", s.Config.ServerConfig.ListenAddr, s.Config.ServerConfig.GrpcPort)
		if err := gs.Serve(lis); err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
	}(s)

	go func() {
		err := sentry.Init(sentry.ClientOptions{
			Dsn:         s.Config.SentryConfig.DNS,
			Environment: s.Config.ServerConfig.Env, //staging or production
		})
		if err != nil {
			s.Log.Error().Err(err).Msg("")
		}
		defer sentry.Flush(2 * time.Second)
	}()

}

// StopServer closes all the connection and shutdown the server
func (s *Server) StopServer() {
	if s.Kafka != nil {
		s.Kafka.Close()
	}
	if s.MongoDB != nil {
		s.MongoDB.Close()
	}
	if s.Redis != nil {
		s.Redis.Close()
	}

	// Close GRPC conn for all clients
	// s.API.App.GrpcClient.Core.Conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.httpServer.Shutdown(ctx); err != nil {
		log.Fatalf("Cannot shutdown server %s", err)
		os.Exit(1)
	}
	os.Exit(0)
}

// InitLoggers initializes all the loggers
func (s *Server) InitLoggers() {
	var kl *logger.KafkaLogWriter
	var cw, fw io.Writer
	if s.Config.LoggerConfig.EnableKafkaLogger {
		dialer := goKafka.NewSegmentioKafkaDialer(&s.Config.KafkaConfig)
		kl = logger.NewKafkaLogWriter(s.Config.LoggerConfig.KafkaLoggerConfig.KafkaTopic, dialer, &s.Config.KafkaConfig)
	}
	if s.Config.LoggerConfig.EnableFileLogger {
		fw = logger.NewFileWriter(s.Config.LoggerConfig.FileLoggerConfig.FileName, s.Config.LoggerConfig.FileLoggerConfig.Path, &s.Config.LoggerConfig.FileLoggerConfig)
	}
	if s.Config.LoggerConfig.EnableConsoleLogger {
		cw = logger.NewZeroLogConsoleWriter(logger.NewStandardConsoleWriter())
	}
	l := logger.NewLogger(kl, cw, fw)

	// Setting logger
	s.Log = l
}

// Used for Staging. Load server's credentials for Server Side TLS connection
func LoadStagingServerTLSCredentials() (credentials.TransportCredentials, error) {
	// Load server's certificate and private key
	// Replace pem files with service specific files
	serverCert, err := tls.LoadX509KeyPair("cert/entity-server-cert.pem", "cert/entity-server-key.pem")
	if err != nil {
		return nil, err
	}

	// Create the credentials and return it
	config := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.NoClientCert,
	}

	return credentials.NewTLS(config), nil
}

// Used for Production. Load server's credentials for Mutual TLS connection
func LoadProdServerTLSCredentials() (credentials.TransportCredentials, error) {
	// Load certificate of the CA who signed client's certificate
	pemClientCA, err := os.ReadFile("cert/ca-cert.pem")
	if err != nil {
		return nil, err
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(pemClientCA) {
		return nil, fmt.Errorf("failed to add client CA's certificate")
	}

	// Load server's certificate and private key
	// Replace pem files with service specific files
	serverCert, err := tls.LoadX509KeyPair("cert/entity-server-cert.pem", "cert/entity-server-key.pem")
	if err != nil {
		return nil, err
	}

	// Create the credentials and return it
	config := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certPool,
	}

	return credentials.NewTLS(config), nil
}

// Load Credentials based on Environment
func LoadGrpcServerCredentials(env string) grpc.ServerOption {
	var tlsCreds credentials.TransportCredentials
	var err error

	if env == "production" {
		tlsCreds, err = LoadProdServerTLSCredentials()
		if err != nil {
			log.Fatalf("failed to load prod grpc server credentials: %v", err)
		}

	} else if env == "staging" {
		tlsCreds, err = LoadStagingServerTLSCredentials()
		if err != nil {
			log.Fatalf("failed to load staging grpc credentials: %v", err)
		}

	} else {
		tlsCreds = insecure.NewCredentials()
	}

	return grpc.Creds(tlsCreds)
}
