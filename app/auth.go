package app

import (
	"context"
	"strings"
	"supportmafia/model"
	"supportmafia/schema"
	"supportmafia/server/auth"
	"time"

	"github.com/markbates/goth"
	uuid "github.com/satori/go.uuid"
	errors "github.com/vasupal1996/goerror"

	"github.com/dgrijalva/jwt-go"
	"github.com/rs/zerolog"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type Auth interface {
	SocialAuth(goth.User) (*schema.SocialAuthResponse, error)
}

// SampleOpts contains arguments to be accepted for new instance of Sample service
type AuthOpts struct {
	App    *App
	DB     *mongo.Database
	Logger *zerolog.Logger
}

// SampleImpl implements Sample service
type AuthImpl struct {
	App    *App
	DB     *mongo.Database
	Logger *zerolog.Logger
}

// InitSample returns initializes Sample service
func InitAuth(opts *AuthOpts) Auth {
	e := &AuthImpl{
		App:    opts.App,
		DB:     opts.DB,
		Logger: opts.Logger,
	}
	return e
}

// Generate a new access and refresh token
func (a *AuthImpl) signSocialToken(userClaim *auth.UserClaim, token_id string) (string, string) {
	// Access token - valid for 60 minutes
	userClaim.Expiry = time.Now().Add(time.Minute * 60).Unix()
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, userClaim)
	accessTokenString, _ := accessToken.SignedString([]byte(a.App.Config.TokenAuthConfig.JWTSignKey))

	// Refresh token - valid for 7 days
	userClaim.Expiry = time.Now().Add(time.Hour * 168).Unix()
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, userClaim)
	refreshTokenString, _ := refreshToken.SignedString([]byte(a.App.Config.TokenAuthConfig.JWTSignKey))

	return accessTokenString, refreshTokenString
}

func (a *AuthImpl) SocialAuth(socialUser goth.User) (*schema.SocialAuthResponse, error) {
	now := time.Now().UTC()
	created := false

	user := &model.User{
		Name:         socialUser.Name,
		Email:        strings.ToLower(socialUser.Email),
		AccessToken:  &socialUser.AccessToken,
		RefreshToken: &socialUser.RefreshToken,
		ExpiresAt:    &socialUser.ExpiresAt,
		IDToken:      &socialUser.IDToken,
	}

	// Check if the user already exists
	userEmailCount, _ := a.DB.Collection(model.UserColl).CountDocuments(context.TODO(), bson.M{"email": socialUser.Email})
	if userEmailCount == 0 {
		// User does not exist
		user.CreatedAt = &now
		res, err := a.DB.Collection(model.UserColl).InsertOne(context.TODO(), user)
		if err != nil {
			err := errors.Wrap(err, "Failed to insert user", &errors.DBError)
			return nil, err
		}
		userID := res.InsertedID.(primitive.ObjectID)
		user.ID = &userID
		created = true
	}

	if !created {
		// Update user details in db
		// Update token
		var dbuser model.User
		err := a.DB.Collection(model.UserColl).FindOne(context.TODO(), bson.M{"email": socialUser.Email}).Decode(&dbuser)
		if err != nil {
			err := errors.Wrap(err, "Failed to get user", &errors.DBError)
			return nil, err
		}
		user.ID = dbuser.ID
		user.UpdatedAt = &now
		filter := bson.M{"email": strings.ToLower(socialUser.Email)}
		update := bson.M{"$set": user}
		opts := options.Update().SetUpsert(true)
		_, err1 := a.DB.Collection(model.UserColl).UpdateOne(context.TODO(), filter, update, opts)
		if err1 != nil {
			return nil, errors.Wrap(err1, "Failed to update the user", &errors.DBError)
		}
	}

	claims := &auth.UserClaim{ID: *user.ID}
	token_id := uuid.NewV4().String()
	accessToken, refreshToken := a.signSocialToken(claims, token_id)
	resp := &schema.SocialAuthResponse{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}

	return resp, nil
}
