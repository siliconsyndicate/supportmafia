package api

import (
	"net/http"
	"supportmafia/server/handler"

	"github.com/markbates/goth/gothic"
	errors "github.com/vasupal1996/goerror"
)

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
