package app

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"supportmafia/model"
	"supportmafia/schema"
	"supportmafia/server/auth"
	"time"

	"github.com/garyburd/redigo/redis"
	"github.com/getsentry/sentry-go"
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
	GenerateRefreshToken(*schema.RefreshToken) (*schema.LoginResponse, error)
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
func (a *AuthImpl) signToken(userClaim *auth.UserClaim, token_id string) (string, string) {
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

// Logout user by deleting their session_id from redis and database
func (a *AuthImpl) deleteSession(session_id string) error {
	// Delete from redis
	_, err := a.App.Redis.Do("DEL", session_id)

	// Delete from db
	filter := bson.M{"session.session_id": session_id}
	update := bson.M{"$pull": bson.M{"session": bson.M{"session_id": session_id}}}
	_, err1 := a.DB.Collection(model.UserColl).UpdateOne(context.TODO(), filter, update)
	if err1 != nil {
		return errors.Wrap(err1, "Failed to update session ID", &errors.DBError)
	}

	return err
}

// Validate token expiry, session id existence and token id existence in redis. Return claims and session data on success
func (a *AuthImpl) ValidateRefreshToken(refreshToken string) (jwt.MapClaims, *auth.UserClaim, error) {
	// Get secret key from config
	secret_key := a.App.Config.TokenAuthConfig.JWTSignKey

	// Validate token and get the session_id into claims variable
	claims := jwt.MapClaims{}
	token, err_jwt := jwt.ParseWithClaims(refreshToken, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret_key), nil
	})

	if err_jwt != nil {
		// Convert jwt error to type jwtValidationError and check if it's a token expired error
		v, _ := err_jwt.(*jwt.ValidationError)

		if v.Errors == jwt.ValidationErrorExpired {
			// Logout user and delete the session id from redis and database
			err := a.deleteSession(claims["session_id"].(string))

			if err != nil {
				sentry.CaptureException(err)
				a.Logger.Err(err).Msgf("Possible malicious activity, failed to delete session %s", claims["session_id"].(string))
				return nil, nil, errors.Wrap(err, "failed to delete session", &errors.SomethingWentWrong)
			}

			return nil, nil, errors.New("Refresh token expired", &errors.Unauthorized)
		}
		if !token.Valid {
			return nil, nil, errors.Wrap(err_jwt, "Invalid refresh token", &errors.PermissionDenied)
		}
		return nil, nil, errors.Wrap(err_jwt, "Failed to parse refresh token", &errors.Unauthorized)
	}

	// Get session data from redis
	var session_data auth.UserClaim
	session_data_str, err := redis.String((a.App.Redis.Do("GET", claims["session_id"])))
	if err != nil {
		return nil, nil, errors.Wrap(err, "Session not found", &errors.Unauthorized)
	}

	// Unmarshal the string into struct
	err1 := json.Unmarshal([]byte(session_data_str), &session_data)
	if err1 != nil {
		return nil, nil, errors.Wrap(err1, "Failed to marshal session data", &errors.Unauthorized)
	}

	// Check if the token id matches in redis and token payload
	if claims["token_id"].(string) != session_data.TokenID {
		// token_id in redis and token payload doesn't match and is being used more than once so something is wrong

		// Logout user and delete the session id from redis and database
		err := a.deleteSession(claims["session_id"].(string))
		if err != nil {
			sentry.CaptureException(err)
			a.Logger.Err(err).Msgf("Possible malicious activity, failed to delete session %s", claims["session_id"].(string))
			return nil, nil, errors.Wrap(err, "failed to delete session", &errors.SomethingWentWrong)
		}
		return nil, nil, errors.New("Unauthorized - Refresh token used twice", &errors.Unauthorized)
	}

	return claims, &session_data, nil
}

// Receive a refresh token and validate it. Return new access and refresh tokens and update new token_id in redis
func (a *AuthImpl) GenerateRefreshToken(t *schema.RefreshToken) (*schema.LoginResponse, error) {

	// Validate incoming refresh token by checking it's expiry and match token id with the session data in redis
	claims, session_data, err := a.ValidateRefreshToken(t.RefreshToken)
	if err != nil {
		return nil, err
	}

	user, err := a.App.User.GetUserByEmail(session_data.Email)
	if err != nil {
		return nil, err
	}

	// Issue a new access and refresh token
	new_token_id := uuid.NewV4().String()
	redis_claims := &auth.UserClaim{}
	user.SetClaim(redis_claims)

	new_claims := &auth.UserClaim{SessionID: claims["session_id"].(string)}
	accessToken, refreshToken := a.signToken(new_claims, new_token_id)

	loginResponse := &schema.LoginResponse{
		RedirectUrl:  t.RedirectUrl,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}

	// Update session data in redis with new token id
	redis_claims.TokenID = new_token_id

	// Convert native struct to json
	session_data_byte, err1 := json.Marshal(redis_claims)
	if err1 != nil {
		return nil, errors.Wrap(err1, "Cannot marshal user", &errors.SomethingWentWrong)
	}

	// Update the session in redis
	_, err2 := a.App.Redis.Do("SET", claims["session_id"].(string), string(session_data_byte))
	if err2 != nil {
		a.Logger.Err(err2).Msgf("Alert, failed to update session %s", claims["session_id"].(string))
		return nil, errors.Wrap(err2, "Failed to update session", &errors.Unauthorized)
	}

	err = a.updateTokenID(session_data.ID, claims["session_id"].(string), new_token_id)
	if err != nil {
		a.Logger.Err(err2).Msgf("Alert, failed to update token ID")
		return nil, errors.Wrap(err2, "Failed to update token id", &errors.Unauthorized)
	}

	return loginResponse, nil
}

// updateTokenID updates the token id associated with a session in DB
func (a *AuthImpl) updateTokenID(userID primitive.ObjectID, sessionID, tokenID string) error {
	filter := bson.M{"_id": userID, "sessions": bson.M{"$elemMatch": bson.M{"session_id": sessionID}}}
	update := bson.M{
		"$set": bson.M{"sessions.$.token_id": tokenID},
	}
	res, err := a.DB.Collection(model.UserColl).UpdateOne(context.TODO(), filter, update)
	if err != nil {
		return errors.Wrap(err, "Failed to query database", &errors.DBError)
	}
	if res.MatchedCount == 0 {
		return errors.New("User Not found", &errors.NotFound)
	}
	if res.ModifiedCount == 0 {
		return errors.New("Failed to update token ID in user session.", &errors.DBError)
	}

	return nil
}

func (a *AuthImpl) SocialAuth(socialUser goth.User) (*schema.SocialAuthResponse, error) {
	now := time.Now().UTC()
	fmt.Printf("%+v\n", socialUser)

	claims := &auth.UserClaim{}
	token_id := uuid.NewV4().String()
	accessToken, refreshToken := a.signSocialToken(claims, token_id)

	user := &model.User{
		Name:        socialUser.Name,
		Email:       strings.ToLower(socialUser.Email),
		AccessToken: &socialUser.AccessToken,
		ExpiresAt:   &socialUser.ExpiresAt,
		IDToken:     &socialUser.IDToken,
	}

	// Check if the user already exists
	userEmailCount, _ := a.DB.Collection(model.UserColl).CountDocuments(context.TODO(), bson.M{"email": socialUser.Email})
	if userEmailCount != 0 {
		// Update user details in db
		// Update token
		user.UpdatedAt = &now
		filter := bson.M{"email": strings.ToLower(socialUser.Email)}
		update := bson.M{"$set": user}
		opts := options.Update().SetUpsert(true)
		_, err1 := a.DB.Collection(model.UserColl).UpdateOne(context.TODO(), filter, update, opts)
		if err1 != nil {
			return nil, errors.Wrap(err1, "Failed to update the user", &errors.DBError)
		}

		var dbuser model.User
		err := a.DB.Collection(model.UserColl).FindOne(context.TODO(), bson.M{"email": socialUser.Email}).Decode(&dbuser)
		if err != nil {
			err := errors.Wrap(err, "Failed to get user", &errors.DBError)
			return nil, err
		}
		user.ID = dbuser.ID

		resp := &schema.SocialAuthResponse{
			User:         user,
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		}

		// Return user
		return resp, nil
	}

	// Create User
	user.CreatedAt = &now
	user.RefreshToken = &socialUser.RefreshToken
	res, err := a.DB.Collection(model.UserColl).InsertOne(context.TODO(), user)
	if err != nil {
		err := errors.Wrap(err, "Failed to insert user", &errors.DBError)
		return nil, err
	}
	if res.InsertedID != nil {
		userID := res.InsertedID.(primitive.ObjectID)
		user.ID = &userID
	}

	resp := &schema.SocialAuthResponse{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}

	return resp, nil
}
