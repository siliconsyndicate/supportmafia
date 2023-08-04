package app

import (
	"context"
	"supportmafia/server/config"
	"supportmafia/server/logger"
	mongostorage "supportmafia/server/storage/mongodb"

	"github.com/pkg/errors"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// NewTestApp returns app instance for testing
func NewTestApp(c *config.Config) *App {
	m := mongostorage.NewMongoStorage(&c.DatabaseConfig)
	l := logger.NewLogger(nil, logger.NewZeroLogConsoleWriter(logger.NewStandardConsoleWriter()), nil)
	a := &App{
		MongoDB: m,
		Logger:  l,
		Config:  &c.APPConfig,
	}
	// Setting up services for test app
	// a.Example = InitExample(&ExampleOpts{App: a, DB: m.Client.Database(a.Config.ExampleConfig.DBName), Logger: l})
	return a
}

// CleanTestApp drops the test database
func CleanTestApp(a *App) {
	ctx := context.Background()
	dbs, _ := a.MongoDB.Client.ListDatabases(ctx, bson.M{"name": bson.M{"$regex": primitive.Regex{Pattern: "^test_*", Options: "i"}}})
	for _, db := range dbs.Databases {
		if err := a.MongoDB.Client.Database(db.Name).Drop(ctx); err != nil {
			a.Logger.Err(errors.Wrap(err, "Cannot drop database"))
		}
	}
}
