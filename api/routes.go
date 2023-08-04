package api

// InitRoutes initializes all the endpoints
func (a *API) InitRoutes() {

	a.Router.Root.Handle("/", a.requestHandler(a.redirect)).Methods("GET")
	a.Router.Root.Handle("/logout", a.requestHandler(a.logoutUser)).Methods("GET")

	// Authentication
	a.Router.Auth.Handle("/refresh_token", a.requestHandler(a.generateRefreshToken)).Methods("POST")
	a.Router.Auth.Handle("/get-user", a.requestWithAuthHandler(a.getLoggedInUser)).Methods("GET")
	a.Router.Auth.Handle("/sign-in", a.requestHandler(a.login)).Methods("POST")
	a.Router.Auth.Handle("/sign-up", a.requestHandler(a.signUp)).Methods("POST")
	a.Router.Auth.Handle("/google/login", a.requestHandler(a.googleLogin)).Methods("GET")
	a.Router.Auth.Handle("/google/callback", a.requestHandler(a.googleCallback)).Methods("GET")
	a.Router.Auth.Handle("/fb/login", a.requestHandler(a.fbLogin)).Methods("GET")
	a.Router.Auth.Handle("/fb/callback", a.requestHandler(a.fbCallback)).Methods("GET")
	a.Router.Auth.Handle("/self-password-reset", a.requestWithAuthHandler(a.resetPasswordOfLoggedinUser)).Methods("POST")
	a.Router.Auth.Handle("/force-password-reset", a.requestWithAuthHandler(a.resetPasswordOfUsers)).Methods("POST")
	a.Router.Auth.Handle("/deactivate", a.requestWithAuthHandler(a.deactivateUser)).Methods("POST")
	a.Router.Auth.Handle("/forgot-password", a.requestHandler(a.forgotPassword)).Methods("POST")
	a.Router.Auth.Handle("/validate-reset-code", a.requestHandler(a.validatePasswordResetCode)).Methods("POST")
	a.Router.Auth.Handle("/reset-password", a.requestHandler(a.resetPassword)).Methods("POST")
	a.Router.Auth.Handle("/script/update_user_structure_es", a.requestWithAuthHandler(a.updateUserStructureES)).Methods("POST")
	a.Router.Auth.Handle("/delete-all-sessions", a.requestWithAuthHandler(a.deleteAllUserSessions)).Methods("GET")
	a.Router.Auth.Handle("/edit-user", a.requestWithAuthHandler(a.editUser)).Methods("POST")

}
