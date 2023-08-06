package api

import (
	"net/http"
	"supportmafia/app"
	"supportmafia/server/auth"
	"supportmafia/server/config"
	"supportmafia/server/handler"
	"supportmafia/server/validator"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
)

// API := returns API struct
type API struct {
	Router      *Router
	MainRouter  *mux.Router
	Logger      *zerolog.Logger
	Config      *config.APIConfig
	TokenAuth   auth.TokenAuth
	SessionAuth auth.SessionAuth
	Validator   *validator.Validator

	App *app.App
}

// Options contain all the dependencies required to create a new instance of api
// and is passed in NewAPI func as argument
type Options struct {
	MainRouter  *mux.Router
	Logger      *zerolog.Logger
	Config      *config.APIConfig
	TokenAuth   auth.TokenAuth
	SessionAuth auth.SessionAuth
	Validator   *validator.Validator
}

// Router stores all the endpoints available for the server to respond.
type Router struct {
	Root       *mux.Router
	APIRoot    *mux.Router
	StaticRoot *mux.Router
	Auth       *mux.Router
	Ticket     *mux.Router
}

// NewAPI returns API instance
func NewAPI(opts *Options) *API {
	api := API{
		MainRouter:  opts.MainRouter,
		Router:      &Router{},
		Config:      opts.Config,
		TokenAuth:   opts.TokenAuth,
		SessionAuth: opts.SessionAuth,
		Logger:      opts.Logger,
		Validator:   opts.Validator,
	}
	api.setupRoutes()
	return &api
}

func (a *API) setupRoutes() {
	a.Router.Root = a.MainRouter
	a.Router.APIRoot = a.MainRouter.PathPrefix("/api").Subrouter()
	a.Router.Auth = a.MainRouter.PathPrefix("/auth").Subrouter()
	a.Router.Ticket = a.MainRouter.PathPrefix("/ticket").Subrouter()
	a.InitRoutes()
	if a.Config.EnableStaticRoute {
		a.Router.StaticRoot = a.MainRouter.PathPrefix("/static").Subrouter()
	}
}

func (a *API) requestHandler(h func(c *handler.RequestContext, w http.ResponseWriter, r *http.Request)) http.Handler {
	return &handler.Request{
		HandlerFunc: h,
		AuthFunc:    a.TokenAuth,
		Environment: a.Config.Mode,
		IsLoggedIn:  false,
	}
}

func (a *API) requestWithAuthHandler(h func(c *handler.RequestContext, w http.ResponseWriter, r *http.Request)) http.Handler {
	return &handler.Request{
		HandlerFunc: h,
		AuthFunc:    a.TokenAuth,
		Environment: a.Config.Mode,
		IsLoggedIn:  true,
	}
}
