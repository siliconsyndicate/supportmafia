package config

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/spf13/viper"
)

// Config struct stores entire project configurations
type Config struct {
	ServerConfig     ServerConfig     `mapstructure:"server"`
	SessionConfig    SessionConfig    `mapstructure:"session"`
	APIConfig        APIConfig        `mapstructure:"api"`
	APPConfig        APPConfig        `mapstructure:"app"`
	KafkaConfig      KafkaConfig      `mapstructure:"kafka"`
	LoggerConfig     LoggerConfig     `mapstructure:"logger"`
	DatabaseConfig   DatabaseConfig   `mapstructure:"database"`
	RedisConfig      RedisConfig      `mapstructure:"redis"`
	MiddlewareConfig MiddlewareConfig `mapstructure:"middleware"`
	TokenAuthConfig  TokenAuthConfig  `mapstructure:"token"`
	MailConfig       MailConfig       `mapstructure:"mail"`
	AWSConfig        AWSConfig        `mapstructure:"aws"`
	CORSConfig       CORSConfig       `mapstructure:"cors"`
	ShopifyConfig    ShopifyConfig    `mapstructure:"shopify"`
	FedexConfig      FedexConfig      `mapstructure:"fedex"`
	QuickbooksConfig QuickbooksConfig `mapstructure:"quickbooks"`
	PDFConfig        PDFConfig        `mapstructure:"pdf"`
	GrpcAddr         GrpcAddr         `mapstructure:"grpcAddr"`
	SentryConfig     SentryConfig     `mapstructure:"sentry"`
	ESConfig         ESConfig         `mapstructure:"elasticsearch"`
	Notification     Notification     `mapstructure:"notification"`
	GoogleOAuth      GoogleOAuth      `mapstructure:"googleOAuth"`
	Goth             Goth             `mapstructure:"goth"`
}

type Goth struct {
	Url string `mapstructure:"url"`
}

type GoogleOAuth struct {
	ClientID     string `mapstructure:"clientId"`
	ClientSecret string `mapstructure:"clientSecret"`
}

type Notification struct {
	APIKey string `mapstructure:"apiKey"`
}

type ESConfig struct {
	Host     string `mapstructure:"host"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
}

type SentryConfig struct {
	DNS string `mapstructure:"dns"`
}

// Stores addresses of all service servers
type GrpcAddr struct {
	Core string `mapstructure:"core"`
}

// ServerConfig has only server specific configuration
type ServerConfig struct {
	ListenAddr     string        `mapstructure:"listenAddr"`
	Port           string        `mapstructure:"port"`
	GrpcPort       string        `mapstructure:"grpcPort"`
	ReadTimeout    time.Duration `mapstructure:"readTimeout"`
	WriteTimeout   time.Duration `mapstructure:"writeTimeout"`
	CloseTimeout   time.Duration `mapstructure:"closeTimeout"`
	Env            string        `mapstructure:"env"`
	GrpcEnv        string        `mapstructure:"grpcEnv"`
	UseMemoryStore bool          `mapstructure:"useMemoryStore"`
}

type SessionConfig struct {
	CookieConfig CookieConfig `mapstructure:"cookie"`
	RedisConfig  RedisConfig
}

type CookieConfig struct {
	Name     string `mapstructure:"name"`
	Path     string `mapstructure:"path"`
	HttpOnly bool   `mapstructure:"httpOnly"`
	Domain   string `mapstructure:"domain"`
	Secure   bool   `mapstructure:"secure"`
}

// ShopifyConfig contains shopify related configurations
type ShopifyConfig struct {
	APIKey       string `mapstructure:"apiKey"`
	APISecretKey string `mapstructure:"apiSecretKey"`
}

// FedEx related configurations
type FedexConfig struct {
	Url string `mapstructure:"url"`
}

// APIConfig contains api package related configurations
type APIConfig struct {
	AWSConfig          AWSConfig
	SessionConfig      SessionConfig
	ShopifyConfig      ShopifyConfig
	Notification       Notification
	GoogleOAuth        GoogleOAuth
	Goth               Goth
	Mode               string `mapstructure:"mode"`
	EnableTestRoute    bool   `mapstructure:"enableTestRoute"`
	EnableMediaRoute   bool   `mapstructure:"enableMediaRoute"`
	EnableStaticRoute  bool   `mapstructure:"enableStaticRoute"`
	MaxRequestDataSize int    `mapstructure:"maxRequestDataSize"`
}

// APPConfig contains api package related configurations
type APPConfig struct {
	DatabaseConfig  DatabaseConfig
	AWSConfig       AWSConfig
	UserConfig      ServiceConfig `mapstructure:"user"`
	Env             string        `mapstructure:"env"`
	TokenAuthConfig TokenAuthConfig
	PDFConfig       PDFConfig
	Notification    Notification

	//INBOUND CONFIGs
	ActivityTrackingProducerConfig ProducerConfig `mapstructure:"activityTrackingProducerConfig"`
	ActivityTrackingConsumerConfig ListenerConfig `mapstructure:"activityTrackingConsumerConfig"`
	InvoicingProducerConfig        ProducerConfig `mapstructure:"invoicingProducerConfig"`

	// Tracking
	TrackingConsumerConfig ListenerConfig `mapstructure:"trackingConsumerConfig"`

	// Fedex
	FedexConfig      FedexConfig
	QuickbooksConfig QuickbooksConfig
}

type QuickbooksConfig struct {
	AuthUrl     string `mapstructure:"auth_url"`
	RedirectUri string `mapstructure:"redirect_uri"`
}

// PDFConfig contains path and name to the html tamplete file for pdf generation
type PDFConfig struct {
	TemplateFileName string `mapstructure:"templateFileName"`
	TemplateFilePath string `mapstructure:"templateFilePath"`
}

// ServiceConfig contains app service related config
type ServiceConfig struct {
	DBName string `mapstructure:"dbName"`
}

// MailConfig has authentication related configuration
type MailConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
	TLS      bool   `mapstructure:"tls"`
	SSL      bool   `mapstructure:"ssl"`
}

// AWSConfig has authentication related configuration
type AWSConfig struct {
	Region          string `mapstructure:"region"`
	UserBucket      string `mapstructure:"userBucket"`
	AccessKeyID     string `mapstructure:"accessKeyId"`
	SecretAccessKey string `mapstructure:"secretAccessKey"`
}

// TokenAuthConfig contains token authentication related configuration
type TokenAuthConfig struct {
	JWTSignKey            string `mapstructure:"jwtSignKey"`
	JWTExpiresAt          int64  `mapstructure:"expiresAt"`
	PasswordHashSecretKey string `mapstructure:"password_hash_secret_key"`
	HmacSecret            string `mapstructure:"hmacSecret"`
	SessionSecretKey      string `mapstructure:"session_secret_key"`
	EmailVerificationKey  string `mapstructure:"email_verification_key"`
	PasswordResetKey      string `mapstructure:"password_reset_key"`
}

// KafkaConfig has kafka cluster specific configuration
type KafkaConfig struct {
	EnableKafka bool     `mapstructure:"enableKafka"`
	BrokerDial  string   `mapstructure:"brokerDial"`
	BrokerURL   string   `mapstructure:"brokerUrl"`
	BrokerPort  string   `mapstructure:"brokerPort"`
	Brokers     []string `mapstructure:"brokers"`
	Username    string   `mapstructure:"username"`
	Password    string   `mapstructure:"password"`
}

// ListenerConfig contains app kafka topic listener related config
type ListenerConfig struct {
	GroupID  string   `mapstructure:"groupId"`
	Brokers  []string `mapstructure:"brokers"`
	Topic    string   `mapstructure:"topic"`
	Username string   `mapstructure:"username"`
	Password string   `mapstructure:"password"`
}

// ProducerConfig contains app kafka topic producer related config
type ProducerConfig struct {
	Brokers  []string `mapstructure:"brokers"`
	Topic    string   `mapstructure:"topic"`
	Async    bool     `mapstructure:"async"`
	Username string   `mapstructure:"username"`
	Password string   `mapstructure:"password"`
}

// LoggerConfig contains different logger configurations
type LoggerConfig struct {
	KafkaLoggerConfig   `mapstructure:"kafkaLog"`
	FileLoggerConfig    `mapstructure:"fileLog"`
	ConsoleLoggerConfig `mapstructure:"consoleLog"`
}

// KafkaLoggerConfig contains kafka logger specific configuration
type KafkaLoggerConfig struct {
	EnableKafkaLogger bool   `mapstructure:"enableKafkaLog"`
	KafkaTopic        string `mapstructure:"kafkaTopic"`
	KafkaPartition    string `mapstructure:"kafkaPartition"`
}

// ConsoleLoggerConfig contains file console logging specific configuration
type ConsoleLoggerConfig struct {
	EnableConsoleLogger bool `mapstructure:"enableConsoleLog"`
}

// FileLoggerConfig contains file logging specific configuration
type FileLoggerConfig struct {
	FileName         string `mapstructure:"fileName"`
	Path             string `mapstructure:"path"`
	EnableFileLogger bool   `mapstructure:"enableFileLog"`
	MaxBackupsFile   int    `mapstructure:"maxBackupFile"`
	MaxSize          int    `mapstructure:"maxFileSize"`
	MaxAge           int    `mapstructure:"maxAge"`
	Compress         bool   `mapstructure:"compress"`
}

// DatabaseConfig contains mongodb related configuration
type DatabaseConfig struct {
	Scheme string `mapstructure:"scheme"`
	Host   string `mapstructure:"host"`
	// DBName     string `mapstructure:"name"`
	Username   string `mapstructure:"username"`
	Password   string `mapstructure:"password"`
	ReplicaSet string `mapstructure:"replicaSet"`
}

// ConnectionURL returns connection string to of mongodb storage
func (d *DatabaseConfig) ConnectionURL() string {
	url := fmt.Sprintf("%s://", d.Scheme)
	if d.Username != "" && d.Password != "" {
		url += fmt.Sprintf("%s:%s@", d.Username, d.Password)
	}
	url += d.Host
	if d.ReplicaSet != "" {
		url += fmt.Sprintf("/?replicaSet=%s", d.ReplicaSet)
	}
	return url
}

// RedisConfig has cache related configuration.
type RedisConfig struct {
	Network  string `mapstructure:"network"`
	Host     string `mapstructure:"host"`
	Port     string `mapstructure:"port"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
}

// ConnectionURL returns connection string to of mongodb storage
func (r *RedisConfig) ConnectionURL() string {
	var url string
	if r.Username != "" {
		url += r.Username
	}
	if r.Password != "" {
		url += fmt.Sprintf(":%s@", r.Password)
	}
	url += r.Host
	if r.Port != "" {
		url += fmt.Sprintf(":%s", r.Port)
	}
	return url
}

// MiddlewareConfig has middlewares related configuration
type MiddlewareConfig struct {
	EnableRequestLog bool `mapstructure:"enableRequestLog"`
}

// GetConfig returns entire project configuration
func GetConfig() *Config {
	return GetConfigFromFile("default")
}

// GetConfigFromFile returns configuration from specific file object
func GetConfigFromFile(fileName string) *Config {
	if fileName == "" {
		fileName = "default"
	}

	// looking for filename `default` inside `src/server` dir with `.toml` extension
	viper.SetConfigName(fileName)
	viper.AddConfigPath("../conf/")
	viper.AddConfigPath("../../conf/")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./conf/")
	viper.SetConfigType("toml")

	err := viper.ReadInConfig()
	if err != nil {
		log.Fatalf("couldn't load config: %s", err)
		os.Exit(1)
	}
	config := &Config{}
	err = viper.Unmarshal(&config)
	if err != nil {
		fmt.Printf("couldn't read config: %s", err)
		os.Exit(1)
	}

	// APP
	config.APPConfig.DatabaseConfig = config.DatabaseConfig
	config.APPConfig.PDFConfig = config.PDFConfig
	config.APPConfig.AWSConfig = config.AWSConfig
	config.APPConfig.TokenAuthConfig = config.TokenAuthConfig
	config.APPConfig.FedexConfig = config.FedexConfig
	config.APPConfig.QuickbooksConfig = config.QuickbooksConfig
	config.APPConfig.Notification = config.Notification
	// API
	config.APIConfig.SessionConfig = config.SessionConfig
	config.APIConfig.ShopifyConfig = config.ShopifyConfig
	config.APIConfig.AWSConfig = config.AWSConfig
	config.APIConfig.Notification = config.Notification
	config.APIConfig.GoogleOAuth = config.GoogleOAuth
	config.APIConfig.Goth = config.Goth
	return config
}

// CORSConfig contains CORS related configurations
type CORSConfig struct {
	AllowedOrigins   []string `mapstructure:"allowed_origins"`
	AllowedMethods   []string `mapstructure:"allowed_methods"`
	AllowCredentials bool     `mapstructure:"allow_credentials"`
	AllowedHeaders   []string `mapstructure:"allowed_headers"`
}
