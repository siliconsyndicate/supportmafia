package api

// InitRoutes initializes all the endpoints
func (a *API) InitRoutes() {

	a.Router.Root.Handle("/", a.requestHandler(a.redirect)).Methods("GET")

	// Social Authentication
	a.Router.Auth.Handle("/get-user", a.requestWithAuthHandler(a.getLoggedInUser)).Methods("GET")
	a.Router.Auth.Handle("/logout/{provider}", a.requestHandler(a.socialLogout)).Methods("GET")
	a.Router.Auth.Handle("/{provider}/callback", a.requestHandler(a.handleCallback)).Methods("GET")
	a.Router.Auth.Handle("/{provider}", a.requestHandler(a.socialAuth)).Methods("GET")

	// Ticket
	a.Router.Ticket.Handle("/create", a.requestWithAuthHandler(a.createTicket)).Methods("POST")
	a.Router.Ticket.Handle("/get-all", a.requestWithAuthHandler(a.getTicketAll)).Methods("GET")
	a.Router.Ticket.Handle("/get", a.requestWithAuthHandler(a.getTicketByID)).Methods("GET")
	a.Router.Ticket.Handle("/prioritize", a.requestWithAuthHandler(a.prioritizeTicket)).Methods("POST")
	a.Router.Ticket.Handle("/resolve", a.requestWithAuthHandler(a.resolveTicket)).Methods("POST")
	a.Router.Ticket.Handle("/assign", a.requestWithAuthHandler(a.assignTicket)).Methods("POST")
	a.Router.Ticket.Handle("/close/user", a.requestWithAuthHandler(a.closeTicketByUser)).Methods("POST")
	a.Router.Ticket.Handle("/close/agent", a.requestWithAuthHandler(a.closeTicketByAgent)).Methods("POST")
	a.Router.Ticket.Handle("/conversation/reply/user", a.requestWithAuthHandler(a.conversationReplyByUser)).Methods("POST")
	a.Router.Ticket.Handle("/conversation/reply/agent", a.requestWithAuthHandler(a.conversationReplyByAgent)).Methods("POST")
	a.Router.Ticket.Handle("/feedback", a.requestWithAuthHandler(a.userFeedback)).Methods("POST")
	a.Router.Ticket.Handle("/reply-all", a.requestWithAuthHandler(a.replyToAllTickets)).Methods("POST")
	a.Router.Ticket.Handle("/conversation/get", a.requestWithAuthHandler(a.getTicketConversation)).Methods("GET")

}
