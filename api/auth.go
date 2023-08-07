package api

import (
	"encoding/json"
	"net/http"
	"supportmafia/schema"
	"supportmafia/server/handler"

	"github.com/markbates/goth/gothic"
	errors "github.com/vasupal1996/goerror"
)

// Validates request data and sends it to the App function
func (a *API) generateRefreshToken(requestCTX *handler.RequestContext, w http.ResponseWriter, r *http.Request) {
	// Checks if request data is empty
	if length := r.ContentLength; length == 0 {
		var err error
		err = errors.Wrap(err, "Empty request data", &errors.BadRequest)
		requestCTX.SetErr(err, 400)
		return
	}

	defer r.Body.Close()

	var refreshTokenForm schema.RefreshToken

	// Read json request data into a native golang struct
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&refreshTokenForm); err != nil {
		err = errors.Wrap(err, "Unable to read json schema", &errors.BadRequest)
		requestCTX.SetErr(err, 400)
		a.Logger.Log().Err(err).Msg("api.verifyToken")
		return
	}

	// Validate if the required keys are present in the refreshTokenForm data as defined in the struct
	if errs := a.Validator.Validate(&refreshTokenForm); errs != nil {
		requestCTX.SetErrs(errs, 400)
		return
	}

	// Validate refresh token and generate new access and refresh token
	response, err := a.App.Auth.GenerateRefreshToken(&refreshTokenForm)
	if err != nil {
		requestCTX.SetErr(err, 401)
		return
	}

	requestCTX.SetAppResponse(response, 200)
}

func (a *API) socialAuth(requestCTX *handler.RequestContext, w http.ResponseWriter, r *http.Request) {
	if user, err := gothic.CompleteUserAuth(w, r); err == nil {
		response, err := a.App.Auth.SocialAuth(user)
		if err != nil {
			requestCTX.SetErr(err, 401)
			return
		}

		requestCTX.SetAppResponse(response, 200)

	} else {
		gothic.BeginAuthHandler(w, r)
	}

}

func (a *API) handleCallback(requestCTX *handler.RequestContext, w http.ResponseWriter, r *http.Request) {
	user, err := gothic.CompleteUserAuth(w, r)
	if err != nil {
		requestCTX.SetErr(err, 401)
		return
	}

	response, err := a.App.Auth.SocialAuth(user)
	if err != nil {
		requestCTX.SetErr(err, 401)
		return
	}

	requestCTX.SetAppResponse(response, 200)
}

func (a *API) socialLogout(requestCTX *handler.RequestContext, w http.ResponseWriter, r *http.Request) {
	err := gothic.Logout(w, r)
	if err != nil {
		requestCTX.SetErr(errors.Wrap(err, "failed to logout user", &errors.BadRequest), 401)
		return
	}

	requestCTX.SetAppResponse(true, 200)
}
