package api

import (
	"net/http"
	"supportmafia/server/auth"
	"supportmafia/server/handler"

	errors "github.com/vasupal1996/goerror"
)

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
