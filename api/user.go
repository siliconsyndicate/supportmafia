package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"supportmafia/model"
	"supportmafia/schema"
	"supportmafia/server/auth"
	"supportmafia/server/handler"

	"github.com/getsentry/sentry-go"
	errors "github.com/vasupal1996/goerror"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
	"golang.org/x/oauth2/google"
)

// logoutUser logs out user and delets the session of the user
func (a *API) logoutUser(requestCTX *handler.RequestContext, w http.ResponseWriter, r *http.Request) {
	// Checks and handels if any panic occurs
	defer a.App.Utils.HandlePanic(requestCTX)

	// deletes the token of user from redis using session id
	err := a.SessionAuth.DeleteToken(requestCTX.SessionID)
	fmt.Println(requestCTX.SessionID)
	if err != nil {
		sentry.CaptureException(err)
	}

	// calling UnSetUserSessionID function and passing email and session id as paramaters, which unsets the session from user in user document
	err = a.App.User.UnSetUserSessionID(requestCTX.UserClaim.(*auth.UserClaim).Email, requestCTX.SessionID)
	if err != nil {
		sentry.CaptureException(err)
	}

	requestCTX.SetAppResponse(map[string]interface{}{"success": true}, 200)
}

// getLoggedInUser fetches the logged in user data from current session
func (a *API) getLoggedInUser(requestCTX *handler.RequestContext, w http.ResponseWriter, r *http.Request) {
	// Checks and handels if any panic occurs
	defer a.App.Utils.HandlePanic(requestCTX)

	// calling UnSetUserSessionID function and passing email and session id as paramaters, which unsets the session from user in user document
	user, err := a.App.User.GetUserByID(requestCTX.UserClaim.(*auth.UserClaim).ID)
	if err != nil {
		requestCTX.SetErr(errors.Wrap(err, "Failed to get user by ID", &errors.DBError), 400)
		return
	}

	requestCTX.SetAppResponse(user, 200)
}

// login logs in and user
func (a *API) login(requestCTX *handler.RequestContext, w http.ResponseWriter, r *http.Request) {
	// Checks and handels if any panic occurs
	defer a.App.Utils.HandlePanic(requestCTX)

	// Checking for request content length for empty request data
	if length := r.ContentLength; length == 0 {
		var err error
		err = errors.Wrap(err, "Empty request data", &errors.BadRequest)
		requestCTX.SetErr(err, 400)
		return
	}

	defer r.Body.Close()
	var loginForm schema.ValidateLoginForm

	// Converting request body data into native golang structure
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&loginForm); err != nil {
		err = errors.Wrap(err, "Unable to read json schema", &errors.BadRequest)
		requestCTX.SetErr(err, 400)
		// a.Logger.Err(err).Msg("api.SignUp")
		return
	}

	// Validator implements value validations for structs and individual fields based on tags
	if errs := a.Validator.Validate(&loginForm); errs != nil {
		requestCTX.SetErrs(errs, 400)
		return
	}

	loginForm.UserAgent = r.UserAgent()
	// Calling function login and passing the login loginForm as parameter, getting user token in response
	loginResponse, userClaim, err := a.App.User.Login(loginForm)
	if err != nil {
		requestCTX.SetErr(err, 500)
		return
	}

	//Logging response data for tracking
	response, _ := json.Marshal(userClaim)
	a.Logger.Log().Str("request_id", requestCTX.RequestID).Str("action", "login").Str("request_status", "responding").Hex("response_data", response).Str("status_code", "200").Msg("Login response data.")

	requestCTX.SetAppResponse(loginResponse, 200)
}

// signUp singns up a new user
func (a *API) signUp(requestCTX *handler.RequestContext, w http.ResponseWriter, r *http.Request) {
	// Checks and handels if any panic occurs
	defer a.App.Utils.HandlePanic(requestCTX)

	// Checking for request content length for empty request data
	if length := r.ContentLength; length == 0 {
		var err error
		err = errors.Wrap(err, "Empty request data", &errors.BadRequest)
		requestCTX.SetErr(err, 400)
		return
	}
	var signUpForm schema.ValidateSignUpForm

	defer r.Body.Close()
	// Converting request body data into native golang structure
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&signUpForm); err != nil {
		err = errors.Wrap(err, "Unable to read json schema", &errors.BadRequest)
		requestCTX.SetErr(err, 400)
		// a.Logger.Err(err).Msg("api.SignUp")
		return
	}

	// Validator implements value validations for structs and individual fields based on tags
	if errs := a.Validator.Validate(&signUpForm); errs != nil {
		requestCTX.SetErrs(errs, 400)
		return
	}

	// Calling function SignUp and passing signUpForm as parameter, getting userr data in response
	user, err := a.App.User.SignUp(&signUpForm)
	if err != nil {
		requestCTX.SetErr(err, 500)
		a.Logger.Err(err).Msg("api.SignUp")
		return
	}

	requestCTX.SetAppResponse(user, 200)
}

// resetPasswordOfLoggedinUser resets self password
func (a *API) resetPasswordOfLoggedinUser(requestCTX *handler.RequestContext, w http.ResponseWriter, r *http.Request) {
	// Checks and handels if any panic occurs
	defer a.App.Utils.HandlePanic(requestCTX)

	// Checking for request content length for empty request data
	if length := r.ContentLength; length == 0 {
		var err error
		err = errors.Wrap(err, "Empty request data", &errors.BadRequest)
		requestCTX.SetErr(err, 400)
		return
	}

	defer r.Body.Close()
	var resetPasswordForm schema.ValidateUserPasswordResetForm

	// Converting request body data into native golang structure
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&resetPasswordForm); err != nil {
		err = errors.Wrap(err, "Unable to read json schema", &errors.BadRequest)
		requestCTX.SetErr(err, 400)
		return
	}

	// Validator implements value validations for structs and individual fields based on tags
	if errs := a.Validator.Validate(&resetPasswordForm); errs != nil {
		requestCTX.SetErrs(errs, 400)
		return
	}
	// Calling ResetPasswordOfUser and passing resetPasswordForm and email as parameters, retuens boolen value true when success
	isDone, err := a.App.User.ResetPasswordOfUser(&resetPasswordForm, requestCTX.UserClaim.(*auth.UserClaim).Email)
	if err != nil {
		requestCTX.SetErr(err, 500)
		a.Logger.Err(err).Msg("api.resetPasswordOfLoggedinUser")
		return
	}

	requestCTX.SetAppResponse(map[string]interface{}{"password_reset": isDone}, 200)
}

// resetPasswordOfUsers used to reset password of other users
func (a *API) resetPasswordOfUsers(requestCTX *handler.RequestContext, w http.ResponseWriter, r *http.Request) {
	// Checks and handels if any panic occurs
	defer a.App.Utils.HandlePanic(requestCTX)

	// Checking for request content length for empty request data
	if length := r.ContentLength; length == 0 {
		var err error
		err = errors.Wrap(err, "Empty request data", &errors.BadRequest)
		requestCTX.SetErr(err, 400)
		return
	}

	defer r.Body.Close()
	var resetPasswordForm schema.ValidateAdminPasswordResetForm

	// Converting request body data into native golang structure
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&resetPasswordForm); err != nil {
		err = errors.Wrap(err, "Unable to read json schema", &errors.BadRequest)
		requestCTX.SetErr(err, 400)
		return
	}

	// Validator implements value validations for structs and individual fields based on tags
	if errs := a.Validator.Validate(&resetPasswordForm); errs != nil {
		requestCTX.SetErrs(errs, 400)
		return
	}
	// Calling ResetPasswordOfOtherUsers function and passing resetPasswordForm and warehouse id as parameters, returns boolean response true when success
	isDone, err := a.App.User.ResetPasswordOfOtherUsers(&resetPasswordForm)
	if err != nil {
		requestCTX.SetErr(err, 500)
		a.Logger.Err(err).Msg("api.resetPasswordOfUsers")
		return
	}

	requestCTX.SetAppResponse(map[string]interface{}{"password_reset": isDone}, 200)
}

// deactivateUser deactivates/halts user from any activity, deletes the session as well
func (a *API) deactivateUser(requestCTX *handler.RequestContext, w http.ResponseWriter, r *http.Request) {
	// Checks and handels if any panic occurs
	defer a.App.Utils.HandlePanic(requestCTX)

	// Checking for request content length for empty request data
	if length := r.ContentLength; length == 0 {
		var err error
		err = errors.Wrap(err, "Empty request data", &errors.BadRequest)
		requestCTX.SetErr(err, 400)
		return
	}

	defer r.Body.Close()
	var deactivateUserForm schema.ValidateDeactivateUser

	// Converting request body data into native golang structure
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&deactivateUserForm); err != nil {
		err = errors.Wrap(err, "Unable to read json schema", &errors.BadRequest)
		requestCTX.SetErr(err, 400)
		return
	}

	// Validator implements value validations for structs and individual fields based on tags
	if errs := a.Validator.Validate(&deactivateUserForm); errs != nil {
		requestCTX.SetErrs(errs, 400)
		return
	}

	// Calling DeactivateUser function and passing deactivateUserForm  in parameter, getting deactivated user data in response
	user, err := a.App.User.DeactivateUser(&deactivateUserForm, requestCTX.UserClaim.(*auth.UserClaim).Name)
	if err != nil {
		requestCTX.SetErr(err, 500)
		a.Logger.Err(err).Msg("api.deactivateUser")
		return
	}
	// deleting all the sessions of the user from redis
	if len(user.Sessions) > 0 {
		for _, session := range user.Sessions {
			if err := a.SessionAuth.DeleteToken(session.SessionID); err != nil {
				requestCTX.SetErr(errors.Wrap(err, "Failed to delete token", &errors.BadRequest), http.StatusBadRequest)
				return
			}
		}
	}

	requestCTX.SetAppResponse(map[string]interface{}{"success": true}, 200)
}

// resetPassword function works together with forgot password which is called after forgot function sends an email
func (a *API) resetPassword(requestCTX *handler.RequestContext, w http.ResponseWriter, r *http.Request) {
	// Checks and handels if any panic occurs
	defer a.App.Utils.HandlePanic(requestCTX)

	// Checking for request content length for empty request data
	if length := r.ContentLength; length == 0 {
		var err error
		err = errors.Wrap(err, "Empty request data", &errors.BadRequest)
		requestCTX.SetErr(err, 400)
		return
	}
	var resetPwdForm schema.ValidatePasswordResetForm

	defer r.Body.Close()
	// Converting request body data into native golang structure
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&resetPwdForm); err != nil {
		err = errors.Wrap(err, "Unable to read json schema", &errors.BadRequest)
		requestCTX.SetErr(err, 400)
		// a.Logger.Err(err).Msg("api.SignUp")
		return
	}

	// Validator implements value validations for structs and individual fields based on tags
	if errs := a.Validator.Validate(&resetPwdForm); errs != nil {
		requestCTX.SetErrs(errs, 400)
		return
	}

	// check if the password and confirm password match
	if resetPwdForm.Password != resetPwdForm.ConfirmPassword {
		err := errors.New("The password did not match with confirm password input.", &errors.BadRequest)
		requestCTX.SetErr(err, 400)
		return
	}

	// calling ResetPassword function and passing  token code and new password as parameters
	isDone, err := a.App.User.ResetPassword(&resetPwdForm)
	if err != nil {
		requestCTX.SetErr(err, 500)
		a.Logger.Err(err).Msg("api.resetForgotPassword")
		return
	}

	requestCTX.SetAppResponse(isDone, 200)
}

// forgotPassword used to reset password of user if they forget their password
func (a *API) forgotPassword(requestCTX *handler.RequestContext, w http.ResponseWriter, r *http.Request) {
	// Checks and handels if any panic occurs
	defer a.App.Utils.HandlePanic(requestCTX)

	// Checking for request content length for empty request data
	if length := r.ContentLength; length == 0 {
		var err error
		err = errors.Wrap(err, "Empty request data", &errors.BadRequest)
		requestCTX.SetErr(err, 400)
		return
	}
	var forgotPwdForm schema.ValidateEmail

	defer r.Body.Close()
	// Converting request body data into native golang structure
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&forgotPwdForm); err != nil {
		err = errors.Wrap(err, "Unable to read json schema", &errors.BadRequest)
		requestCTX.SetErr(err, 400)
		// a.Logger.Err(err).Msg("api.SignUp")
		return
	}

	// Validator implements value validations for structs and individual fields based on tags
	if errs := a.Validator.Validate(&forgotPwdForm); errs != nil {
		requestCTX.SetErrs(errs, 400)
		return
	}

	//calling ForgotPassword function and passing users email in parameter
	user, err := a.App.User.ForgotPassword(forgotPwdForm.Email)
	if err != nil {
		requestCTX.SetErr(err, 500)
		a.Logger.Err(err).Msg("api.forgotPassword")
		return
	}
	// deleting all the sessions of the user from redis
	if len(user.Sessions) > 0 {
		for _, session := range user.Sessions {
			if err := a.SessionAuth.DeleteToken(session.SessionID); err != nil {
				requestCTX.SetErr(errors.Wrap(err, "Failed to remove existing session", &errors.BadRequest), http.StatusBadRequest)
				return
			}
		}
	}

	requestCTX.SetAppResponse(true, 200)
}

// checks if the OTP entered by the user is valid
func (a *API) validatePasswordResetCode(requestCTX *handler.RequestContext, w http.ResponseWriter, r *http.Request) {
	// Checks and handels if any panic occurs
	defer a.App.Utils.HandlePanic(requestCTX)

	// Checking for request content length for empty request data
	if length := r.ContentLength; length == 0 {
		var err error
		err = errors.Wrap(err, "Empty request data", &errors.BadRequest)
		requestCTX.SetErr(err, 400)
		return
	}
	var validateResetForm schema.ValidatePasswordResetCode

	defer r.Body.Close()
	// Converting request body data into native golang structure
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&validateResetForm); err != nil {
		err = errors.Wrap(err, "Unable to read json schema", &errors.BadRequest)
		requestCTX.SetErr(err, 400)
		// a.Logger.Err(err).Msg("api.SignUp")
		return
	}

	// Validator implements value validations for structs and individual fields based on tags
	if errs := a.Validator.Validate(&validateResetForm); errs != nil {
		requestCTX.SetErrs(errs, 400)
		return
	}

	// calling ValidatePasswordResetCode function and passing user's email and OTP in parameter
	success, err := a.App.User.ValidatePasswordResetCode(&validateResetForm)
	if err != nil {
		requestCTX.SetErr(err, 500)
		a.Logger.Err(err).Msg("api.passwordResetCodeValidation")
		return
	}

	requestCTX.SetAppResponse(success, 200)
}

// fetches all the user access profiles of a warehouse
func (a *API) updateUserStructureES(requestCTX *handler.RequestContext, w http.ResponseWriter, r *http.Request) {
	// Checks and handels if any panic occurs
	defer a.App.Utils.HandlePanic(requestCTX)

	//calling get access profiles function with warehouse id as parameter
	profiles, err := a.App.User.UpdateUserStructureES()
	if err != nil {
		requestCTX.SetErr(err, 500)
		a.Logger.Err(err).Msg("api.GetAccessProfiles")
		return
	}

	requestCTX.SetAppResponse(profiles, 200)
}

// deleteAllUserSessions deletes all existing user sessions
func (a *API) deleteAllUserSessions(requestCTX *handler.RequestContext, w http.ResponseWriter, r *http.Request) {
	// Checks and handels if any panic occurs
	defer a.App.Utils.HandlePanic(requestCTX)

	//calling DeleteAllUserSessionss function
	isDone, err := a.App.User.DeleteAllUserSessions()
	if err != nil {
		requestCTX.SetErr(err, 500)
		a.Logger.Err(err).Msg("api.GetAccessProfiles")
		return
	}

	requestCTX.SetAppResponse(isDone, 200)
}

// editUser edit User data
func (a *API) editUser(requestCTX *handler.RequestContext, w http.ResponseWriter, r *http.Request) {
	// Checks and handels if any panic occurs
	defer a.App.Utils.HandlePanic(requestCTX)

	// Checking for request content length for empty request data
	if length := r.ContentLength; length == 0 {
		var err error
		err = errors.Wrap(err, "Empty request data", &errors.BadRequest)
		requestCTX.SetErr(err, 400)
		return
	}

	defer r.Body.Close()
	var editUserForm schema.ValidateEditUser

	// Converting request body data into native golang structure
	v := r.FormValue("data")
	if err := json.Unmarshal([]byte(v), &editUserForm); err != nil {
		err = errors.Wrap(err, "Unable to read json schema", &errors.BadRequest)
		requestCTX.SetErr(err, 400)
		return
	}

	// Validator implements value validations for structs and individual fields based on tags
	if errs := a.Validator.Validate(&editUserForm); errs != nil {
		requestCTX.SetErrs(errs, 400)
		return
	}

	if editUserForm.UserID == nil {
		editUserForm.UserID = &requestCTX.UserClaim.(*auth.UserClaim).ID
	}

	// reading file from request data
	f, fn, err := r.FormFile("file")
	if f != nil {
		if err != nil {
			e := errors.Wrap(err, "Failed to read file", &errors.BadRequest)
			requestCTX.SetErr(e, 400)
			return
		}
		defer f.Close()
		// Parsing request form
		if err := r.ParseForm(); err != nil {
			e := errors.Wrap(err, "Failed to read file", &errors.BadRequest)
			requestCTX.SetErr(e, 400)
			return
		}
		buf := new(bytes.Buffer)
		if _, err := io.Copy(buf, f); err != nil {
			requestCTX.SetErr(err, 400)
			return
		}
		// Adding files to Amazon S3 and saving the returned string to updateShipmentForm
		fileUrl, err := a.App.SSS.AddFileToS3WithID(editUserForm.UserID.Hex(), a.Config.AWSConfig.UserBucket, fn.Size, buf.Bytes())
		if err != nil {
			e := errors.Wrap(err, "Failed to upload document to S3.", &errors.SomethingWentWrong)
			requestCTX.SetErr(e, 500)
			return
		}
		editUserForm.Image = fileUrl
	}

	//Logging request data for tracking
	userClaim, _ := json.Marshal(requestCTX.UserClaim.(*auth.UserClaim))
	a.Logger.Log().Str("request_id", requestCTX.RequestID).Str("request_status", "initiating").Str("action", "edit_user").Hex("request_data", []byte(v)).Hex("user_claim", userClaim).Msg("Edit user request data.")

	//Calling EditUser function and passing editUserForm as parameters
	user, err := a.App.User.EditUser(&editUserForm, requestCTX.SessionID)
	if err != nil {
		a.Logger.Log().Str("request_id", requestCTX.RequestID).Str("action", "edit_user").Str("status_code", "500").Err(err).Msg("Edit user error response.")
		requestCTX.SetErr(err, 500)
		return
	}

	//Logging response data for tracking
	response, _ := json.Marshal(user)
	a.Logger.Log().Str("request_id", requestCTX.RequestID).Str("action", "edit_user").Str("request_status", "responding").Hex("response_data", response).Str("status_code", "200").Msg("Edit user response data.")

	requestCTX.SetAppResponse(user, 200)
}

// googleLogin logs in user using google
func (a *API) googleLogin(requestCTX *handler.RequestContext, w http.ResponseWriter, r *http.Request) {
	// Checks and handels if any panic occurs
	defer a.App.Utils.HandlePanic(requestCTX)

	// Oauth configuration for Google
	googleConfig := oauth2.Config{
		ClientID:     a.Config.GoogleOAuth.ClientID,
		ClientSecret: a.Config.GoogleOAuth.ClientSecret,
		Endpoint:     google.Endpoint,
		RedirectURL:  "http://localhost:8000/google/callback",
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
	}

	url := googleConfig.AuthCodeURL("randomstate")

	requestCTX.SetAppResponse(url, 200)
}

// googleCallback to get google response
func (a *API) googleCallback(requestCTX *handler.RequestContext, w http.ResponseWriter, r *http.Request) {
	// Checks and handels if any panic occurs
	defer a.App.Utils.HandlePanic(requestCTX)

	// check is method is correct
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	OauthGoogleUrlAPI := "https://www.googleapis.com/oauth2/v2/userinfo?access_token="
	// Oauth configuration for Google
	googleConfig := oauth2.Config{
		ClientID:     a.Config.GoogleOAuth.ClientID,
		ClientSecret: a.Config.GoogleOAuth.ClientSecret,
		Endpoint:     google.Endpoint,
		RedirectURL:  "http://localhost:8000/google/callback",
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
	}

	// get oauth state from cookie for this user
	state := r.FormValue("state")
	code := r.FormValue("code")
	w.Header().Add("content-type", "application/json")

	// ERROR : Invalid OAuth State
	if state != "randomstate" {
		err := errors.New("Invalid oauth google state", &errors.BadRequest)
		requestCTX.SetErr(err, 400)
		return
	}

	// Exchange Auth Code for Tokens
	token, err := googleConfig.Exchange(context.TODO(), code)
	// ERROR : Auth Code Exchange Failed
	if err != nil {
		err := errors.New("Falied code exchange:", &errors.BadRequest)
		requestCTX.SetErr(err, 400)
		return
	}

	// Fetch User Data from google server
	resp, err := http.Get(OauthGoogleUrlAPI + token.AccessToken)
	// ERROR : Unable to get user data from google
	if err != nil {
		err := errors.New("Failed to get user info:", &errors.BadRequest)
		requestCTX.SetErr(err, 400)
		return
	}

	// Parse user data JSON Object
	defer resp.Body.Close()
	contents, err := io.ReadAll(resp.Body)
	if err != nil {
		err := errors.New("Failed to read response:", &errors.BadRequest)
		requestCTX.SetErr(err, 400)
		return
	}

	var result *model.GooleUserData
	json.Unmarshal([]byte(contents), &result) //translating json response into a model structure

	//Calling GoogleLogin function
	loginResponse, userClaim, err := a.App.User.GoogleLogin(result)
	if err != nil {
		a.Logger.Log().Str("request_id", requestCTX.RequestID).Str("action", "google_login").Str("status_code", "500").Err(err).Msg("Google Login error response.")
		requestCTX.SetErr(err, 500)
		return
	}

	//Logging response data for tracking
	response, _ := json.Marshal(userClaim)
	a.Logger.Log().Str("request_id", requestCTX.RequestID).Str("action", "google_login").Str("request_status", "responding").Hex("response_data", response).Str("status_code", "200").Msg("Google Login response data.")

	requestCTX.SetAppResponse(loginResponse, 200)
}

// fbLogin logs in user using facebook
func (a *API) fbLogin(requestCTX *handler.RequestContext, w http.ResponseWriter, r *http.Request) {
	// Checks and handels if any panic occurs
	defer a.App.Utils.HandlePanic(requestCTX)

	// Oauth configuration for Google
	fbConfig := oauth2.Config{
		ClientID:     a.Config.FacebookOAuth.ClientID,
		ClientSecret: a.Config.FacebookOAuth.ClientSecret,
		Endpoint:     facebook.Endpoint,
		RedirectURL:  "http://localhost:3000/fb/callback",
		Scopes: []string{
			"email",
			"public_profile",
		},
	}

	url := fbConfig.AuthCodeURL("randomstate")

	requestCTX.SetRedirectResponse(url, 200)
}

// fbCallback to get fb response
func (a *API) fbCallback(requestCTX *handler.RequestContext, w http.ResponseWriter, r *http.Request) {
	// Checks and handels if any panic occurs
	defer a.App.Utils.HandlePanic(requestCTX)

	// check is method is correct
	if r.Method != "GET" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	OauthFacebookUrlAPI := "https://graph.facebook.com/v13.0/me?fields=id,name,email,picture&access_token="
	// Oauth configuration for Google
	fbConfig := oauth2.Config{
		ClientID:     a.Config.FacebookOAuth.ClientID,
		ClientSecret: a.Config.FacebookOAuth.ClientSecret,
		Endpoint:     facebook.Endpoint,
		RedirectURL:  "http://localhost:3000/fb/callback",
		Scopes: []string{
			"email",
			"public_profile",
		},
	}

	// get oauth state from cookie for this user
	state := r.FormValue("state")
	code := r.FormValue("code")
	w.Header().Add("content-type", "application/json")

	// ERROR : Invalid OAuth State
	if state != "randomstate" {
		err := errors.New("invalid oauth google state", &errors.BadRequest)
		requestCTX.SetErr(err, 400)
		return
	}

	// Exchange Auth Code for Tokens
	token, err := fbConfig.Exchange(context.Background(), code)
	// ERROR : Auth Code Exchange Failed
	if err != nil {
		err := errors.New("Falied code exchange:", &errors.BadRequest)
		requestCTX.SetErr(err, 400)
		return
	}

	// Fetch User Data from facebook server
	response, err := http.Get(OauthFacebookUrlAPI + token.AccessToken)
	// ERROR : Unable to get user data from google
	if err != nil {
		err := errors.New("Failed to get user info:", &errors.BadRequest)
		requestCTX.SetErr(err, 400)
		return
	}

	// Parse user data JSON Object
	defer response.Body.Close()
	contents, err := io.ReadAll(response.Body)
	if err != nil {
		err := errors.New("Failed to read response:", &errors.BadRequest)
		requestCTX.SetErr(err, 400)
		return
	}

	requestCTX.SetAppResponse(string(contents), 200)
}
