package app

import (
	"supportmafia/server/auth"
	"supportmafia/server/config"
	elastic "supportmafia/server/storage/elasticsearch"
	mongostorage "supportmafia/server/storage/mongodb"
	redisstorage "supportmafia/server/storage/redis"

	"github.com/rs/zerolog"
)

// Options contains arguments required to create a new app instance
type Options struct {
	SessionAuth auth.SessionAuth
	MongoDB     *mongostorage.MongoStorage
	Redis       *redisstorage.RedisStorage
	ES          *elastic.ElasticSearch
	Logger      *zerolog.Logger
	Config      *config.APPConfig
	GrpcClient  *GrpcClient
}

// App := contains resources to implement business logic
type App struct {
	SessionAuth auth.SessionAuth
	MongoDB     *mongostorage.MongoStorage
	Redis       *redisstorage.RedisStorage
	ES          *elastic.ElasticSearch
	Logger      *zerolog.Logger
	Config      *config.APPConfig

	// Grpc
	GrpcClient *GrpcClient

	// AWS service
	SES SES
	SSS SSS

	//Services
	Utils  Utils
	User   User
	Auth   Auth
	Ticket Ticket

	// KAFKA
	// ActivityTrackingProducer kafka.Producer
	// ActivityTrackingConsumer kafka.Consumer
}

// NewApp returns new app instance
func NewApp(opts *Options) *App {
	return &App{
		SessionAuth: opts.SessionAuth,
		MongoDB:     opts.MongoDB,
		Redis:       opts.Redis,
		ES:          opts.ES,
		Logger:      opts.Logger,
		Config:      opts.Config,
		SES:         NewSESImpl(&SESImplOpts{Config: &opts.Config.AWSConfig}),
		SSS:         NewSSSImpl(&SSSImplOpts{Config: &opts.Config.AWSConfig}),
		GrpcClient:  opts.GrpcClient,
	}
}

// Contains GRPC clients
type GrpcClient struct {
	//Core *Core
	// Add new GRPC clients here
}

// // Core client
// type Core struct {
// 	Client core_proto.CoreClient
// 	Conn   *grpc.ClientConn
// }
