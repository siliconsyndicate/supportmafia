package app

import (
	"context"
	"supportmafia/model"

	"github.com/opensearch-project/opensearch-go"
	"github.com/rs/zerolog"
	errors "github.com/vasupal1996/goerror"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// User defines methods of user service to be implemented
type User interface {
	GetUserByID(primitive.ObjectID) (*model.User, error)
}

// UserOpts contains arguments to be accepted for new instance of user service
type UserOpts struct {
	App    *App
	DB     *mongo.Database
	ES     *opensearch.Client
	Logger *zerolog.Logger
}

// UserImpl implements user service
type UserImpl struct {
	App    *App
	DB     *mongo.Database
	ES     *opensearch.Client
	Logger *zerolog.Logger
}

// InitUser returns initializes user service
func InitUser(opts *UserOpts) User {
	e := &UserImpl{
		App:    opts.App,
		DB:     opts.DB,
		ES:     opts.ES,
		Logger: opts.Logger,
	}
	return e
}

// GetUserByID fetches user by user id
func (a *UserImpl) GetUserByID(user_id primitive.ObjectID) (*model.User, error) {
	var user *model.User
	if err := a.DB.Collection(model.UserColl).FindOne(context.TODO(), bson.M{"_id": user_id}).Decode(&user); err != nil {
		e := errors.Wrap(err, "Failed to find by ID", &errors.NotFound)
		return nil, e
	}
	return user, nil
}
