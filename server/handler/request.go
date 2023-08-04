package handler

import (
	"encoding/json"
	"net/http"
	"supportmafia/server/auth"
	"supportmafia/server/middleware"

	"github.com/gorilla/mux"
	errors "github.com/vasupal1996/goerror"
)

// Request represents a request from client
type Request struct {
	HandlerFunc func(*RequestContext, http.ResponseWriter, *http.Request)
	AuthFunc    auth.TokenAuth
	Environment string
	IsLoggedIn  bool
}

// HandleRequest := handles incoming requests from client
func (rh *Request) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestCTX := &RequestContext{}
	requestCTX.RequestID = middleware.RequestIDFromContext(r.Context())
	requestCTX.Path = r.URL.Path

	name := mux.CurrentRoute(r).GetName()
	authToken := r.Header.Get("Authorization")
	if authToken != "" && authToken != "open" {
		claim, sessionID, err := rh.AuthFunc.VerifyToken(authToken)
		if err != nil {
			requestCTX.SetErr(errors.Wrap(err, "Failed to verify token", &errors.PermissionDenied), http.StatusUnauthorized)
			goto SKIP_REQUEST
		} else {
			requestCTX.SessionID = sessionID
			requestCTX.UserClaim = claim.(*auth.UserClaim)
		}
	}
	if rh.IsLoggedIn {
		if requestCTX.UserClaim == nil {
			requestCTX.SetErr(errors.New("Auth token required", &errors.PermissionDenied), http.StatusUnauthorized)
			goto SKIP_REQUEST
		} else {
			if !requestCTX.UserClaim.IsGranted(name) {
				requestCTX.SetErr(errors.New("permission denied: operation on this client is not authorized", &errors.PermissionDenied), http.StatusForbidden)
				goto SKIP_REQUEST
			}
		}
	}

SKIP_REQUEST:

	w.Header().Set(auth.HeaderRequestID, requestCTX.RequestID)
	if requestCTX.Err == nil {
		rh.HandlerFunc(requestCTX, w, r)
	}

	switch t := requestCTX.ResponseType; t {
	case HTMLResp:
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(requestCTX.ResponseCode)
		res := requestCTX.Response.GetRaw()
		if _, err := w.Write(res.([]byte)); err != nil {
			requestCTX.SetErr(errors.New("Could not write response", &errors.SomethingWentWrong), http.StatusInternalServerError)
		}
	case JSONResp:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(requestCTX.ResponseCode)
		if err := json.NewEncoder(w).Encode(requestCTX.Response); err != nil {
			requestCTX.SetErr(errors.New("Could not encode response", &errors.SomethingWentWrong), http.StatusInternalServerError)
		}
	case ErrorResp:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(requestCTX.ResponseCode)
		requestCTX.Err.RequestID = &requestCTX.RequestID
		if err := json.NewEncoder(w).Encode(&requestCTX.Err); err != nil {
			requestCTX.SetErr(errors.New("Could not encode response", &errors.SomethingWentWrong), http.StatusInternalServerError)
		}
	case RedirectResp:
		res, _ := requestCTX.Response.MarshalJSON()
		http.Redirect(w, r, string(res), requestCTX.ResponseCode)
	}

}
