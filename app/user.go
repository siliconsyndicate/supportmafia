package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"supportmafia/model"
	"supportmafia/schema"
	"supportmafia/server/auth"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ses"
	"github.com/dgrijalva/jwt-go"
	"github.com/getsentry/sentry-go"
	"github.com/opensearch-project/opensearch-go"
	"github.com/opensearch-project/opensearch-go/opensearchutil"
	"github.com/rs/zerolog"
	uuid "github.com/satori/go.uuid"
	errors "github.com/vasupal1996/goerror"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// User defines methods of user service to be implemented
type User interface {
	Login(schema.ValidateLoginForm) (*schema.LoginResponse, *auth.UserClaim, error)
	UnSetUserSessionID(string, string) error
	UpdateUserToken(primitive.ObjectID) ([]byte, error)
	SignUp(*schema.ValidateSignUpForm) (*model.User, error)
	ResetPasswordOfUser(*schema.ValidateUserPasswordResetForm, string) (bool, error)
	ResetPasswordOfOtherUsers(*schema.ValidateAdminPasswordResetForm) (bool, error)
	DeactivateUser(*schema.ValidateDeactivateUser, string) (*model.User, error)
	ResetPassword(*schema.ValidatePasswordResetForm) (bool, error)
	ForgotPassword(string) (*model.User, error)
	ValidatePasswordResetCode(*schema.ValidatePasswordResetCode) (bool, error)
	GetUserByID(primitive.ObjectID) (*model.User, error)
	GetUserByEmail(string) (*model.User, error)
	UpdateUserStructureES() (bool, error)
	DeleteAllUserSessions() (bool, error)
	EditUser(*schema.ValidateEditUser, string) (*model.User, error)
	GoogleLogin(*model.GooleUserData) (*schema.LoginResponse, *auth.UserClaim, error)
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

// UpdateUserToken update user token
func (a *UserImpl) UpdateUserToken(userID primitive.ObjectID) ([]byte, error) {
	// Fetching user by user id
	user, err := a.GetUserByID(userID)
	if err != nil {
		return nil, err
	}

	// Mapping user to user claim struct
	userClaim := &auth.UserClaim{}
	user.SetClaim(userClaim)
	userClaim_str, err := json.Marshal(userClaim)
	if err != nil {
		return nil, errors.Wrap(err, "Cannot marshal user.", &errors.SomethingWentWrong)
	}
	return userClaim_str, nil
}

// SetUserSessionID sets user session related data into user collection
func (a *UserImpl) SetUserSessionID(email, sessionID, userAgent, tokenID string) error {
	now := time.Now().UTC()
	UserSession := model.UserSessionDetails{
		SessionID: sessionID,
		TokenID:   tokenID,
		CreatedAt: &now,
	}
	filter := bson.M{"email": email}
	update := bson.M{"$push": bson.M{"sessions": UserSession}}
	_, err := a.DB.Collection(model.UserColl).UpdateOne(context.TODO(), filter, update)
	if err != nil {
		return errors.Wrap(err, "Failed to update session ID", &errors.DBError)
	}
	return nil
}

// UnSetUserSessionID unsets user session related data into user collection
func (a *UserImpl) UnSetUserSessionID(email, sessionID string) error {
	filter := bson.M{"email": email}
	update := bson.M{"$pull": bson.M{"sessions": bson.M{"session_id": sessionID}}}
	_, err := a.DB.Collection(model.UserColl).UpdateOne(context.TODO(), filter, update)
	if err != nil {
		return errors.Wrap(err, "Failed to update session ID", &errors.DBError)
	}
	return nil
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

// getUserByEmail fetches user by email
func (a *UserImpl) GetUserByEmail(email string) (*model.User, error) {
	var user *model.User
	if err := a.DB.Collection(model.UserColl).FindOne(context.TODO(), bson.M{"email": email}).Decode(&user); err != nil {
		if err == mongo.ErrNoDocuments {
			e := errors.New("Access denied! User not found with this email.", &errors.NotFound)
			return nil, e
		} else {
			e := errors.Wrap(err, "Failed to find user with provided email", &errors.NotFound)
			a.Logger.Err(e).Msg("{getUserByEmail}")
			return nil, e
		}
	}
	return user, nil
}

// loginViaEmail accepts user email and password and logs user in the app
func (a *UserImpl) loginViaEmail(email, password, userAgent string) (*schema.LoginResponse, *auth.UserClaim, error) {
	// fetching user by email
	user, err := a.GetUserByEmail(email)
	if err != nil {
		return nil, nil, err
	}

	// checking is user password is valid or not
	isValid := user.CheckPassword(password)
	if !isValid {
		err := errors.New("Access denied! Password is invalid.", &errors.PermissionDenied)
		return nil, nil, err
	}
	// checking if the user is deactivated user
	if user.IsDeactivated {
		return nil, nil, errors.New("Access denied! User is Deactivated.", &errors.PermissionDenied)
	}

	// Generate token_id and save it along with other session items in redis
	token_id := uuid.NewV4().String()

	// mapping user to userclaim struct
	userClaim := &auth.UserClaim{}
	user.SetClaim(userClaim)
	userClaim.TokenID = token_id

	// encoding userclaim to json
	userClaim_str, err := json.Marshal(userClaim)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Cannot marshal user.", &errors.SomethingWentWrong)
	}
	// Setting user session
	sessionID, err := a.App.SessionAuth.Set(string(userClaim_str))
	if err != nil {
		return nil, nil, err
	}
	// Setting session Id in user collection
	err = a.SetUserSessionID(email, sessionID, userAgent, token_id)
	if err != nil {
		return nil, nil, err
	}

	claims := &auth.UserClaim{}
	claims.SessionID = sessionID
	// Generating jwt access and refresh token
	accessToken, refreshToken := a.signToken(claims, token_id)

	user.Sessions = nil
	user.Password = ""

	loginResponse := &schema.LoginResponse{
		RedirectUrl:  "/",
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User:         user,
	}
	return loginResponse, userClaim, nil
}

// Login login a user
func (a *UserImpl) Login(v schema.ValidateLoginForm) (*schema.LoginResponse, *auth.UserClaim, error) {
	return a.loginViaEmail(v.Email, v.Password, v.UserAgent)
}

// SignToken := creates a token
func (a *UserImpl) signToken(userClaim *auth.UserClaim, token_id string) (string, string) {

	// Access token
	userClaim.Expiry = time.Now().Add(time.Minute * 60).Unix()
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, userClaim)
	accessTokenString, _ := accessToken.SignedString([]byte(a.App.Config.TokenAuthConfig.JWTSignKey))

	// Refresh token
	userClaim.Expiry = time.Now().Add(time.Hour * 168).Unix()
	userClaim.TokenID = token_id
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, userClaim)
	refreshTokenString, _ := refreshToken.SignedString([]byte(a.App.Config.TokenAuthConfig.JWTSignKey))

	return accessTokenString, refreshTokenString
}

// SignUp user into the database
func (a *UserImpl) SignUp(v *schema.ValidateSignUpForm) (*model.User, error) {
	// checking if user already exists or not
	userEmailCount, _ := a.DB.Collection(model.UserColl).CountDocuments(context.TODO(), bson.M{"email": v.Email})
	if userEmailCount != 0 {
		err := errors.New("User with this email already exists", &errors.DBError)
		return nil, err
	}
	return a.createUser(v.Name, v.Email, v.Password, v.Gender)
}

// createUser creates user while signUp
func (a *UserImpl) createUser(name, email, password, gender string) (*model.User, error) {
	now := time.Now()
	var wg sync.WaitGroup
	user := &model.User{
		Name:      name,
		Email:     strings.ToLower(email),
		CreatedAt: &now,
	}

	if gender != "" {
		user.Gender = gender
	}
	// Validating password for alphanumeric password
	err := a.ValidatePassowrd(password)
	if err != nil {
		return nil, err
	}
	//setting password in user
	wg.Add(1)
	go func() {
		defer wg.Done()
		user.SetPassword(password)
	}()
	wg.Wait()

	// wg.Add(1)
	// var confirmationCodeErr error
	// go func(u *model.User, e error) {
	// 	defer wg.Done()
	// 	e = a.generateConfirmationCode(u)
	// }(user, confirmationCodeErr)

	// wg.Wait()
	// if confirmationCodeErr != nil {
	// 	return nil, errors.Wrap(confirmationCodeErr, "Failed to generate confirmation email")
	// }
	// wg.Add(1)
	// var verificationMailErr error
	// go func(u *model.User, e error) {
	// 	defer wg.Done()
	// 	e = a.sendVerificationEmail(u)
	// }(user, verificationMailErr)

	// Inserting new user into database
	res, err := a.DB.Collection(model.UserColl).InsertOne(context.TODO(), user)
	if err != nil {
		err := errors.Wrap(err, "OperationFailed", &errors.DBError)
		return nil, err
	}
	if res.InsertedID != nil {
		userID := res.InsertedID.(primitive.ObjectID)
		user.ID = &userID
	}
	wg.Wait()

	// var isVerificationEmailSent bool

	// if verificationMailErr == nil {
	// 	isVerificationEmailSent = true
	// }
	user.Password = ""
	user.ConfirmationCode = ""
	return user, nil
}

// ValidatePassowrd checks the password if it is alphanumeric or not
func (a *UserImpl) ValidatePassowrd(password string) error {
	// checking for uppercase alphabet
	IsUpper, _ := regexp.MatchString("[A-Z]", password)
	if !IsUpper {
		err := errors.New("Should have atlest 1 Upper case alphabet", &errors.PermissionDenied)
		return err
	}
	// checking for loweercase alphabet
	IsLower, _ := regexp.MatchString("[a-z]", password)
	if !IsLower {
		err := errors.New("Should have atlest 1 Lower case alphabet", &errors.PermissionDenied)
		return err
	}
	// checking for a number
	IsNumber, _ := regexp.MatchString("[0-9]", password)
	if !IsNumber {
		err := errors.New("Should have atlest a number", &errors.PermissionDenied)
		return err
	}
	// checking for any special character
	IsSpecialChar, _ := regexp.MatchString("[#?!@$%^&*-]", password)
	if !IsSpecialChar {
		err := errors.New("Should have atleast 1 special character", &errors.PermissionDenied)
		return err
	}
	return nil
}

// ResetPasswordOfUser restes password of logged in user/ self password reset
func (a *UserImpl) ResetPasswordOfUser(v *schema.ValidateUserPasswordResetForm, email string) (bool, error) {
	// fetching user by email
	user, err := a.GetUserByEmail(email)
	if err != nil {
		return false, err
	}
	// checking if current password is correct or not
	isValid := user.CheckPassword(v.CurrentPassword)
	if !isValid {
		err := errors.New("Invalid password", &errors.PermissionDenied)
		return false, err
	}
	// checking is password is vaild or not
	err = a.ValidatePassowrd(v.Password)
	if err != nil {
		return false, err
	}
	user.SetPassword(v.Password)

	// updating user with new password in database
	update := bson.M{"$set": bson.M{"password": user.Password, "password_reset_code": ""}}
	_, err = a.DB.Collection(model.UserColl).UpdateOne(context.TODO(), bson.M{"email": email}, update)
	if err != nil {
		e := errors.Wrap(err, "Failed to update password", &errors.DBError)
		return false, e
	}

	return true, nil
}

// ResetPasswordOfOtherUsers resets password of other user by user id
func (a *UserImpl) ResetPasswordOfOtherUsers(v *schema.ValidateAdminPasswordResetForm) (bool, error) {
	// fetching user by user id
	user, err := a.GetUserByID(v.UserID)
	if err != nil {
		return false, err
	}
	// checking is password is vaild or not
	err = a.ValidatePassowrd(v.Password)
	if err != nil {
		return false, err
	}
	user.SetPassword(v.Password)

	// updating user with new password in database
	update := bson.M{"$set": bson.M{"password": user.Password, "password_reset_code": ""}}
	_, err = a.DB.Collection(model.UserColl).UpdateOne(context.TODO(), bson.M{"_id": v.UserID}, update)
	if err != nil {
		e := errors.Wrap(err, "Failed to update password", &errors.DBError)
		return false, e
	}

	return true, nil
}

// DeactivateUser deactivates or activates user on basis of account status code
func (a *UserImpl) DeactivateUser(v *schema.ValidateDeactivateUser, username string) (*model.User, error) {
	now := time.Now().UTC()
	// fetching user by user id
	user, err := a.GetUserByID(v.UserID)
	if err != nil {
		return nil, err
	}
	filter := bson.M{"_id": v.UserID}
	var update bson.M
	// checking if the account status code is 0 of 1, if 0 deactivate the user otherwise activate
	if v.SetAccountStatus == 0 {
		if user.IsDeactivated {
			return nil, errors.New("User account is already deactivated.", &errors.SomethingWentWrong)
		}
		update = bson.M{
			"$set": bson.M{
				"is_deactivated":      true,
				"deactivated_at":      now,
				"deactivated_by":      username,
				"deactivation_reason": v.DeactivationReason,
			},
			"$unset": bson.M{
				"sessions": "",
			},
		}

	} else {
		update = bson.M{
			"$set": bson.M{
				"is_deactivated": false,
			},
			"$unset": bson.M{
				"deactivated_at":      "",
				"deactivated_by":      "",
				"deactivation_reason": "",
			},
		}
	}
	err = a.DB.Collection(model.UserColl).FindOneAndUpdate(context.TODO(), filter, update).Decode(&user)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to activate/deactivate user ", &errors.DBError)
	}

	return user, nil
}

// generateResetPasswordCode generates token for password reset when user forgots the password
func (a *UserImpl) generateResetPasswordCode(u *model.User) error {
	// claims := &jwt.StandardClaims{
	// 	ExpiresAt: time.Unix(time.Now().Unix(), 0).Add(time.Minute * 15).Unix(),
	// 	Issuer:    u.Email,
	// 	IssuedAt:  time.Now().Unix(),
	// }
	// // generating token
	// token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// ss, err := token.SignedString([]byte(a.App.Config.TokenAuthConfig.PasswordResetKey))
	// if err != nil {
	// 	return err
	// }
	otp := 1000 + rand.Intn(9999-1000)
	expiry := time.Unix(time.Now().Unix(), 0).Add(time.Minute * 15)
	u.SetPasswordResetCode(strconv.Itoa(otp), expiry)
	return nil
}

// ForgotPassword sends password reset link to user email
func (a *UserImpl) ForgotPassword(email string) (*model.User, error) {
	// fetching user by email
	user, err := a.GetUserByEmail(email)
	if err != nil {
		return nil, err
	}
	if user.IsDeactivated {
		return nil, errors.New("The user with provided email is deactivated!", &errors.Unauthorized)
	}
	// generating password reset code/token
	if err = a.generateResetPasswordCode(user); err != nil {
		return nil, errors.Wrap(err, "Failed to generate password reset code", &errors.SomethingWentWrong)
	}

	// updating user with password reset token
	update := bson.M{
		"$set": bson.M{
			"password_reset_code":   user.PasswordResetCode,
			"reset_code_expiration": user.ResetCodeExpiration,
		},
		"$unset": bson.M{"sessions": 1},
	}
	_, err = a.DB.Collection(model.UserColl).UpdateOne(context.TODO(), bson.M{"_id": user.ID}, update)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to set password reset code in user", &errors.SomethingWentWrong)
	}
	if err = a.SendPasswordResetEmail(user); err != nil {
		e := errors.Wrap(err, "Failed to send password reset email", &errors.SomethingWentWrong)
		return nil, e
	}

	user.PasswordResetCode = ""
	return user, nil
}

// SendPasswordResetEmail send verification email to user
func (a *UserImpl) SendPasswordResetEmail(u *model.User) error {
	template := fmt.Sprintf(`
			<p>Dear %s,</p>
			<p><b>%s</b> is your OTP (One Time Password) to complete the password reset process.</p>
			<p>Please enter this OTP on the password reset page and create a new password to recover your Leanafy account.</p>
			<p>This OTP is valid for 15 minutes. Please use it within the time frame to reset your password. If you did not initiate this request, please contact your admin.</p>
			<br>
			<p>Cheers!</p>
			<p>Team Leanafy!</p>
			<br>
			<br>
			<p><i>This is an auto generated email. Please do not reply to it. If you have any questions or need assistance, please contact us at support@leanafy.com.</i></p>`,
		u.Name, u.PasswordResetCode)
	input := &ses.SendEmailInput{
		Destination: &ses.Destination{
			ToAddresses: []*string{
				aws.String(u.Email),
			},
		},
		Message: &ses.Message{
			Body: &ses.Body{
				Html: &ses.Content{
					Charset: aws.String("utf-8"),
					Data:    aws.String(template),
				},
			},
			Subject: &ses.Content{
				Charset: aws.String("utf-8"),
				Data:    aws.String("Leanafy account recovery"),
			},
		},
		Source: aws.String("no-reply@leanafy.com"),
	}
	if a.App.Config.Env == "production" || a.App.Config.Env == "staging" {
		_, err := a.App.SES.SendEmail(input)
		if err != nil {
			errInfo := "Failed to send verification email to: " + u.Email
			a.Logger.Err(err).Msgf(errInfo)
			return errors.Wrap(err, errInfo, &errors.SomethingWentWrong)
		}
	}
	return nil
}

// ResetPassword resets password
func (a *UserImpl) ValidatePasswordResetCode(otp *schema.ValidatePasswordResetCode) (bool, error) {
	email := otp.Email

	var user *model.User
	if err := a.DB.Collection(model.UserColl).FindOne(context.TODO(), bson.M{"email": email}).Decode(&user); err != nil {
		e := errors.Wrap(err, "Failed to find user with provided email", &errors.NotFound)
		return false, e
	}

	if user.PasswordResetCode == otp.Code {

		now := time.Now()

		if now.After(*user.ResetCodeExpiration) {
			return false, errors.New("OTP Expired!", &errors.PermissionDenied)
		}

	} else {
		err := errors.New("Incorrect OTP!", &errors.Unauthorized)
		return false, err
	}

	return true, nil
}

// ResetPassword resets password
func (a *UserImpl) ResetPassword(reset *schema.ValidatePasswordResetForm) (bool, error) {
	email := reset.Email

	// Checking if the new password is correct or not
	err := a.ValidatePassowrd(reset.Password)
	if err != nil {
		return false, err
	}
	var user *model.User
	if err := a.DB.Collection(model.UserColl).FindOne(context.TODO(), bson.M{"email": email}).Decode(&user); err != nil {
		e := errors.Wrap(err, "Failed to find user with provided email", &errors.NotFound)
		return false, e
	}

	if user.PasswordResetCode == reset.Code {

		now := time.Now()
		valsToSet := bson.M{
			"password_reset_code":   "",
			"reset_code_expiration": "",
		}
		var err1 error
		var err2 error

		if now.After(*user.ResetCodeExpiration) {
			err1 = errors.New("OTP Expired!", &errors.PermissionDenied)
		} else {
			user.SetPassword(reset.Password)
			valsToSet["password"] = user.Password
		}

		// updaring user with new password
		update := bson.M{"$set": bson.M{"password": user.Password, "password_reset_code": ""}}
		_, e := a.DB.Collection(model.UserColl).UpdateOne(context.TODO(), bson.M{"email": email}, update)
		if e != nil {
			err2 = errors.Wrap(err, "Failed to update password", &errors.DBError)
		}

		if err1 != nil {
			return false, err1
		} else if err2 != nil {
			return false, err2
		}

	} else {
		err := errors.New("Incorrect OTP!", &errors.Unauthorized)
		return false, err
	}

	return true, nil
}

// // CreateSubUser creates a new sub user
// func (a *UserImpl) CreateSubUser(v *schema.ValidateCreateOrganizationUser, organizationID primitive.ObjectID, creatingUser model.UserModel) (interface{}, error) {

// 	// Checking if same email already exists in database
// 	emailCount, err := a.DB.Collection(model.UserColl).CountDocuments(context.TODO(), bson.M{"email": v.Email})
// 	if err != nil {
// 		e := errors.Wrap(err, "Failed to check for email", &errors.DBError)
// 		return false, e
// 	}
// 	if emailCount != 0 {
// 		e := errors.New("email already taken", &errors.PermissionDenied)
// 		return false, e
// 	}
// 	return a.createSubUser(organizationID, v.Username, v.Password, v.Email, v.Name, v.Gender, creatingUser)
// }

// createSubUser creates a new user which is already associated with an organization and warehouse,
// creating a new user of warehouse
// func (a *UserImpl) createSubUser(orgID primitive.ObjectID, username, password, email, name, gender string, creatingUser model.UserModel) (interface{}, error) {
// 	now := time.Now().UTC()
// 	// mapping user data into struct
// 	user := &model.User{
// 		Name:        name,
// 		Email:       email,
// 		Gender:      gender,
// 		Username: username,
// 		CreatedAt:   &now,
// 		CreatedBy:   &creatingUser,
// 	}
// 	// checking if the password is correct or not
// 	err := a.ValidatePassowrd(password)
// 	if err != nil {
// 		return false, err
// 	}
// 	user.SetPassword(password)

// 	// creating session for atomic updates
// 	session, err := a.DB.Client().StartSession()
// 	if err != nil {
// 		return false, errors.Wrap(err, "Unable to create db session", &errors.DBError)
// 	}
// 	// Closing session at the end for function execution
// 	defer session.EndSession(context.TODO())

// 	// staring a new transaction
// 	if err := session.StartTransaction(); err != nil {
// 		return false, errors.Wrap(err, "Unable to start transaction", &errors.DBError)
// 	}

// 	if err := mongo.WithSession(context.TODO(), session, func(sc mongo.SessionContext) error {
// 		// Inserting new user into database
// 		res, err := a.DB.Collection(model.UserColl).InsertOne(sc, user)
// 		if err != nil {
// 			if err := session.AbortTransaction(sc); err != nil {
// 				return errors.Wrap(err, "Failed to abort create new user transaction", &errors.DBError)
// 			}
// 			return errors.Wrap(err, "Failed to create new user", &errors.DBError)
// 		}

// 		userID := res.InsertedID.(primitive.ObjectID)

// 		// Insert into elasticsearch

// 		// Build the request body.
// 		es_req_data, err := json.Marshal(user)
// 		if err != nil {
// 			sentry.CaptureException(errors.Wrap(err, "failed to insert user in elasticsearch", &errors.SomethingWentWrong))
// 		}

// 		es_res, err := a.ES.Index(
// 			"user",                                  // Index name
// 			strings.NewReader(string(es_req_data)),  // Document body
// 			a.ES.Index.WithDocumentID(userID.Hex()), // Document ID
// 			a.ES.Index.WithRefresh("true"),          // Refresh
// 		)
// 		if err != nil {
// 			sentry.CaptureException(errors.Wrap(err, "failed to insert user in elasticsearch", &errors.SomethingWentWrong))
// 		}
// 		if es_res.IsError() {
// 			e := errors.New(es_res.String(), &errors.DBError)
// 			sentry.CaptureException(errors.Wrap(e, "failed to insert user in elasticsearch", &errors.SomethingWentWrong))
// 		}
// 		defer es_res.Body.Close()

// 		user.ID = &userID

// 		if err := session.CommitTransaction(sc); err != nil {
// 			return errors.Wrap(err, "Failed to commit", &errors.DBError)
// 		}
// 		return nil
// 	}); err != nil {
// 		a.Logger.Err(err).Msg("createSubUser.mongo.WithSession")
// 		return nil, err
// 	}
// 	user.Password = ""

// 	return user, err
// }

// GetUserAccess fetches user access details
func (a *UserImpl) UpdateUserStructureES() (bool, error) {
	var users []model.User
	cur, err := a.DB.Collection(model.UserColl).Find(context.TODO(), bson.M{})
	if err != nil {
		return false, errors.Wrap(err, "Failed to query database", &errors.DBError)
	}
	if err := cur.All(context.TODO(), &users); err != nil {
		return false, errors.Wrap(err, "Failed to find users", &errors.DBError)
	}

	// Bulk index to ES
	bi, err := opensearchutil.NewBulkIndexer(opensearchutil.BulkIndexerConfig{
		Index:         "user",           // The default index name
		Client:        a.ES,             // The Elasticsearch client
		NumWorkers:    runtime.NumCPU(), // The number of worker goroutines
		FlushBytes:    5,                // The flush threshold in bytes
		FlushInterval: 30 * time.Second, // The periodic flush interval
	})
	if err != nil {
		sentry.CaptureException(errors.Wrap(err, "failed to create bulk indexer", &errors.SomethingWentWrong))
		return false, errors.Wrap(err, "failed to create bulk indexer", &errors.DBError)
	}
	var countSuccessful uint64

	for _, user := range users {

		// Append to ES bulk indexer
		es_data, err := json.Marshal(user)
		if err != nil {
			sentry.CaptureException(errors.Wrap(err, "failed to marshal user", &errors.SomethingWentWrong))
			return false, errors.Wrap(err, "failed to marshal user", &errors.DBError)
		}

		// store code as a string in ES
		var es_req_data_map map[string]interface{}
		err = json.Unmarshal(es_data, &es_req_data_map)
		if err != nil {
			return false, errors.Wrap(err, "failed to unmarshal user", &errors.DBError)
		}
		delete(es_req_data_map, "_id")

		es_data, err = json.Marshal(es_req_data_map)
		if err != nil {
			return false, errors.Wrap(err, "could not marshal user", &errors.DBError)
		}

		// Add an item to the BulkIndexer
		err = bi.Add(
			context.TODO(),
			opensearchutil.BulkIndexerItem{
				// Action field configures the operation to perform (index, create, delete, update)
				Action: "index",

				// DocumentID is the (optional) document ID
				DocumentID: user.ID.Hex(),

				// Body is an `io.Reader` with the payload
				Body: bytes.NewReader(es_data),

				// OnSuccess is called for each successful operation
				OnSuccess: func(ctx context.Context, item opensearchutil.BulkIndexerItem, res opensearchutil.BulkIndexerResponseItem) {
					atomic.AddUint64(&countSuccessful, 1)
				},

				// OnFailure is called for each failed operation
				OnFailure: func(ctx context.Context, item opensearchutil.BulkIndexerItem, res opensearchutil.BulkIndexerResponseItem, err error) {
					sentry.CaptureException(errors.Wrap(err, "failed to bulk insert user", &errors.SomethingWentWrong))
					if err != nil {
						log.Printf("ERROR: %s", err)
					} else {
						log.Printf("ERROR: %s: %s", res.Error.Type, res.Error.Reason)
					}
				},
			},
		)
		if err != nil {
			sentry.CaptureException(errors.Wrap(err, "failed to bulk insert user", &errors.SomethingWentWrong))
			return false, errors.Wrap(err, "failed to bulk insert user", &errors.DBError)
		}
	}

	// Close bulk indexer
	if err := bi.Close(context.TODO()); err != nil {
		sentry.CaptureException(errors.Wrap(err, "failed to bulk insert user", &errors.SomethingWentWrong))
		return false, errors.Wrap(err, "failed to bulk insert user", &errors.DBError)
	}

	// Check the indexing stats
	biStats := bi.Stats()
	if biStats.NumFailed > 0 {
		e := "number of documents failed to index" + strconv.FormatInt(int64(biStats.NumFailed), 10)
		sentry.CaptureException(errors.New(e, &errors.SomethingWentWrong))
		return false, errors.Wrap(err, "failed to bulk insert user", &errors.DBError)
	}

	return true, nil
}

// DeleteAllUserSessions deletes all user sessions from redis and db
func (u *UserImpl) DeleteAllUserSessions() (bool, error) {
	fmt.Println("Session wipe-out initiated!")
	sessionCount := 0

	// fetch all keys from redis
	keys, err := u.App.SessionAuth.GetAllKeys()
	if err != nil {
		return false, errors.Wrap(err, "Failed to fetch keys", &errors.DBError)
	}

	// loop over all keys and check if the key is a valid uuid
	for _, key := range keys {
		keyData := uuid.FromStringOrNil(key)
		if keyData != uuid.Nil {
			sessionCount++
			if err := u.App.SessionAuth.DeleteToken(key); err != nil {
				return false, errors.Wrap(err, "Failed to delete token", &errors.BadRequest)
			}
		}
	}

	fmt.Println("Session count: ", sessionCount)

	// delete sessions from all users in database
	update := bson.M{
		"$unset": bson.M{"sessions": 1},
	}
	res, err := u.DB.Collection(model.UserColl).UpdateMany(context.TODO(), bson.M{}, update)
	if err != nil {
		return false, errors.Wrap(err, "Failed to query database", &errors.DBError)
	}
	if res.MatchedCount == 0 {
		return false, errors.New("Users not Found", &errors.NotFound)
	}

	fmt.Println("User count: ", res.ModifiedCount)

	fmt.Println("ALL SESSIONS DELETED!")

	return true, nil
}

func (u *UserImpl) EditUser(v *schema.ValidateEditUser, sessionID string) (*model.User, error) {
	set := bson.M{}
	if len(v.Image) > 0 {
		set["image"] = v.Image
	}
	if len(v.Name) > 0 {
		set["name"] = v.Name
	}
	filter := bson.M{"_id": v.UserID}
	update := bson.M{
		"$set": set,
	}
	res, err := u.DB.Collection(model.UserColl).UpdateOne(context.TODO(), filter, update)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to query database", &errors.DBError)
	}
	if res.MatchedCount == 0 {
		return nil, errors.New("User not Found", &errors.NotFound)
	}
	if res.ModifiedCount == 0 {
		return nil, errors.New("Failed to update user!", &errors.NotFound)
	}

	user, err := u.GetUserByID(*v.UserID)
	if err != nil {
		return nil, err
	}
	// mapping user to userclaim struct
	userClaim := &auth.UserClaim{}
	user.SetClaim(userClaim)
	for _, session := range user.Sessions {
		if session.SessionID == sessionID {
			userClaim.TokenID = session.TokenID
			// encoding userclaim to json
			userClaim_str, err := json.Marshal(userClaim)
			if err != nil {
				return nil, errors.Wrap(err, "Cannot marshal user.", &errors.SomethingWentWrong)
			}
			// Setting user session
			err = u.App.SessionAuth.SetToken(session.SessionID, string(userClaim_str))
			if err != nil {
				return nil, err
			}
		}
	}
	user.Sessions = nil
	user.Password = ""

	return user, nil
}

func (u *UserImpl) createNewUser(email, name, image, googleID string) (*primitive.ObjectID, error) {
	now := time.Now().UTC()
	user := &model.User{
		Name:      name,
		Email:     strings.ToLower(email),
		Image:     image,
		GoogleID:  googleID,
		CreatedAt: &now,
	}
	// Inserting new user into database
	res, err := u.DB.Collection(model.UserColl).InsertOne(context.TODO(), user)
	if err != nil {
		err := errors.Wrap(err, "OperationFailed", &errors.DBError)
		return nil, err
	}
	if res.InsertedID != nil {
		userID := res.InsertedID.(primitive.ObjectID)
		user.ID = &userID
	}
	return user.ID, nil
}

func (u *UserImpl) GoogleLogin(v *model.GooleUserData) (*schema.LoginResponse, *auth.UserClaim, error) {
	// Checking if same email already exists in database
	emailCount, err := u.DB.Collection(model.UserColl).CountDocuments(context.TODO(), bson.M{"email": v.Email})
	if err != nil {
		e := errors.Wrap(err, "Failed to check for email", &errors.DBError)
		return nil, nil, e
	}
	if v.Hd == nil {
		if *v.Hd != "leanafy.com" {
			return nil, nil, errors.New("Access Denied! You are mot a leanafy user.", &errors.PermissionDenied)
		}
		return nil, nil, errors.New("Access Denied! Please login with your business email.", &errors.PermissionDenied)
	}
	if emailCount > 0 {
		return u.loginViaGoogle(v.Email)
	} else {

		_, err := u.createNewUser(v.Email, v.Name, v.Image, v.GoogleID)
		if err != nil {
			return nil, nil, err
		}

		return u.loginViaGoogle(v.Email)
	}

}

// loginViaGoogle accepts user email and logs user in the app
func (a *UserImpl) loginViaGoogle(email string) (*schema.LoginResponse, *auth.UserClaim, error) {
	// fetching user by email
	user, err := a.GetUserByEmail(email)
	if err != nil {
		return nil, nil, err
	}

	// checking if the user is deactivated user
	if user.IsDeactivated {
		return nil, nil, errors.New("Access denied! User is Deactivated.", &errors.PermissionDenied)
	}

	// Generate token_id and save it along with other session items in redis
	token_id := uuid.NewV4().String()

	// mapping user to userclaim struct
	userClaim := &auth.UserClaim{}
	user.SetClaim(userClaim)
	userClaim.TokenID = token_id

	// encoding userclaim to json
	userClaim_str, err := json.Marshal(userClaim)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Cannot marshal user.", &errors.SomethingWentWrong)
	}
	// Setting user session
	sessionID, err := a.App.SessionAuth.Set(string(userClaim_str))
	if err != nil {
		return nil, nil, err
	}
	// Setting session Id in user collection
	err = a.SetUserSessionID(email, sessionID, "", token_id)
	if err != nil {
		return nil, nil, err
	}

	claims := &auth.UserClaim{}
	claims.SessionID = sessionID
	// Generating jwt access and refresh token
	accessToken, refreshToken := a.signToken(claims, token_id)

	user.Sessions = nil
	user.Password = ""

	loginResponse := &schema.LoginResponse{
		RedirectUrl:  "/",
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User:         user,
	}
	return loginResponse, userClaim, nil
}
