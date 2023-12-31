package api

import (
	"supportmafia/app"
	"supportmafia/server/config"
	"supportmafia/server/logger"

	"github.com/gorilla/mux"
)

// NewTestAPI returns api struct for unit testing
func NewTestAPI(c *config.APIConfig) *API {
	l := logger.NewLogger(nil, logger.NewZeroLogConsoleWriter(logger.NewStandardConsoleWriter()), nil)
	api := &API{
		MainRouter: &mux.Router{},
		Router:     &Router{},
		Config:     c,
		Logger:     l,
	}
	api.setupRoutes()
	api.App = &app.App{}
	return api
}
