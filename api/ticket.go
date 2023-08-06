package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"supportmafia/schema"
	"supportmafia/server/auth"
	"supportmafia/server/handler"

	errors "github.com/vasupal1996/goerror"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// createTicket is used to create a new ticket
func (a *API) createTicket(requestCTX *handler.RequestContext, w http.ResponseWriter, r *http.Request) {
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
	var createTicketForm schema.ValidateCreateTicket

	// Converting request body data into native golang structure
	v := r.FormValue("data")
	if err := json.Unmarshal([]byte(v), &createTicketForm); err != nil {
		err = errors.Wrap(err, "Unable to read json schema", &errors.BadRequest)
		requestCTX.SetErr(err, 400)
		return
	}

	// Validator implements value validations for structs and individual fields based on tags
	if errs := a.Validator.Validate(&createTicketForm); errs != nil {
		requestCTX.SetErrs(errs, 400)
		return
	}

	var attachemnts []string
	for i := 0; i < createTicketForm.NumFile; i++ {
		// reading file from request data
		name := "file_" + strconv.Itoa(i)
		f, fn, err := r.FormFile(name)
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
			fileUrl, err := a.App.SSS.AddFileToS3(fn.Filename, a.Config.AWSConfig.UserBucket, fn.Size, buf.Bytes())
			if err != nil {
				e := errors.Wrap(err, "Failed to upload document to S3.", &errors.SomethingWentWrong)
				requestCTX.SetErr(e, 500)
				return
			}
			attachemnts = append(attachemnts, fileUrl)
		}
	}
	createTicketForm.Attachments = attachemnts

	//Logging request data for tracking
	userClaim, _ := json.Marshal(requestCTX.UserClaim.(*auth.UserClaim))
	a.Logger.Log().Str("request_id", requestCTX.RequestID).Str("request_status", "initiating").Str("action", "create_ticket").Hex("request_data", []byte(v)).Hex("user_claim", userClaim).Msg("Create Ticket request data.")

	//Calling CreateTicket function and passing createTicketForm as parameters
	ticket, err := a.App.Ticket.CreateTicket(&createTicketForm)
	if err != nil {
		a.Logger.Log().Str("request_id", requestCTX.RequestID).Str("action", "create_ticket").Str("status_code", "500").Err(err).Msg("Create Ticket error response.")
		requestCTX.SetErr(err, 500)
		return
	}

	//Logging response data for tracking
	response, _ := json.Marshal(ticket)
	a.Logger.Log().Str("request_id", requestCTX.RequestID).Str("action", "create_ticket").Str("request_status", "responding").Hex("response_data", response).Str("status_code", "200").Msg("Create Ticket response data.")

	requestCTX.SetAppResponse(ticket, 200)
}

// getTicketAll is used to get all ticket
func (a *API) getTicketAll(requestCTX *handler.RequestContext, w http.ResponseWriter, r *http.Request) {
	// Checks and handels if any panic occurs
	defer a.App.Utils.HandlePanic(requestCTX)

	status := r.URL.Query().Get("status")
	user := r.URL.Query().Get("name")

	// Calling GetTicketAll function and passing status,user name as paramaters
	arn, err := a.App.Ticket.GetTicketAll(status, user)
	if err != nil {
		requestCTX.SetErr(err, 500)
		return
	}

	requestCTX.SetAppResponse(arn, 200)
}

// getTicketByID is used to get all ticket
func (a *API) getTicketByID(requestCTX *handler.RequestContext, w http.ResponseWriter, r *http.Request) {
	// Checks and handels if any panic occurs
	defer a.App.Utils.HandlePanic(requestCTX)

	// fetching ticket id from request query
	ticketID, err := primitive.ObjectIDFromHex(r.URL.Query().Get("ticket_id"))
	if err != nil {
		requestCTX.SetErr(errors.New("Invalid ticketID in request query", &errors.BadRequest), 400)
		return
	}

	// Calling GetTicketByID function and passing status,user name as paramaters
	arn, err := a.App.Ticket.GetTicketByID(ticketID)
	if err != nil {
		requestCTX.SetErr(err, 500)
		return
	}

	requestCTX.SetAppResponse(arn, 200)
}

// prioritizeTicket sets the priority of a ticket
func (a *API) prioritizeTicket(requestCTX *handler.RequestContext, w http.ResponseWriter, r *http.Request) {
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
	var prioritizeTicketForm schema.ValidatePrioritizeTicket

	// Converting request body data into native golang structure
	v := r.FormValue("data")
	if err := json.Unmarshal([]byte(v), &prioritizeTicketForm); err != nil {
		err = errors.Wrap(err, "Unable to read json schema", &errors.BadRequest)
		requestCTX.SetErr(err, 400)
		return
	}

	// Validator implements value validations for structs and individual fields based on tags
	if errs := a.Validator.Validate(&prioritizeTicketForm); errs != nil {
		requestCTX.SetErrs(errs, 400)
		return
	}

	//Logging request data for tracking
	userClaim, _ := json.Marshal(requestCTX.UserClaim.(*auth.UserClaim))
	a.Logger.Log().Str("request_id", requestCTX.RequestID).Str("request_status", "initiating").Str("action", "prioritize_ticket").Hex("request_data", []byte(v)).Hex("user_claim", userClaim).Msg("Prioritize Ticket request data.")

	//Calling PrioritizeTicket function and passing prioritizeTicketForm as parameters
	ticket, err := a.App.Ticket.PrioritizeTicket(&prioritizeTicketForm)
	if err != nil {
		a.Logger.Log().Str("request_id", requestCTX.RequestID).Str("action", "prioritize_ticket").Str("status_code", "500").Err(err).Msg("Prioritize Ticket error response.")
		requestCTX.SetErr(err, 500)
		return
	}

	//Logging response data for tracking
	response, _ := json.Marshal(ticket)
	a.Logger.Log().Str("request_id", requestCTX.RequestID).Str("action", "prioritize_ticket").Str("request_status", "responding").Hex("response_data", response).Str("status_code", "200").Msg("Prioritize Ticket response data.")

	requestCTX.SetAppResponse(ticket, 200)
}

// resolveTicket sets the status of a ticket to resolved
func (a *API) resolveTicket(requestCTX *handler.RequestContext, w http.ResponseWriter, r *http.Request) {
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
	var resolveTicketForm schema.ValidateResolveTicket

	// Converting request body data into native golang structure
	v := r.FormValue("data")
	if err := json.Unmarshal([]byte(v), &resolveTicketForm); err != nil {
		err = errors.Wrap(err, "Unable to read json schema", &errors.BadRequest)
		requestCTX.SetErr(err, 400)
		return
	}

	// Validator implements value validations for structs and individual fields based on tags
	if errs := a.Validator.Validate(&resolveTicketForm); errs != nil {
		requestCTX.SetErrs(errs, 400)
		return
	}

	resolveTicketForm.ResolvedBy = &schema.UserModel{
		UserID: requestCTX.UserClaim.(*auth.UserClaim).ID,
		Name:   requestCTX.UserClaim.(*auth.UserClaim).Name,
		Email:  requestCTX.UserClaim.(*auth.UserClaim).Email,
	}

	//Logging request data for tracking
	userClaim, _ := json.Marshal(requestCTX.UserClaim.(*auth.UserClaim))
	a.Logger.Log().Str("request_id", requestCTX.RequestID).Str("request_status", "initiating").Str("action", "resolve_ticket").Hex("request_data", []byte(v)).Hex("user_claim", userClaim).Msg("Resolve Ticket request data.")

	//Calling ResolveTicket function and passing resolveTicketForm as parameters
	ticket, err := a.App.Ticket.ResolveTicket(&resolveTicketForm)
	if err != nil {
		a.Logger.Log().Str("request_id", requestCTX.RequestID).Str("action", "resolve_ticket").Str("status_code", "500").Err(err).Msg("Resolve Ticket error response.")
		requestCTX.SetErr(err, 500)
		return
	}

	//Logging response data for tracking
	response, _ := json.Marshal(ticket)
	a.Logger.Log().Str("request_id", requestCTX.RequestID).Str("action", "resolve_ticket").Str("request_status", "responding").Hex("response_data", response).Str("status_code", "200").Msg("Resolve Ticket response data.")

	requestCTX.SetAppResponse(ticket, 200)
}

// assignTicket assigns a ticket to a agent
func (a *API) assignTicket(requestCTX *handler.RequestContext, w http.ResponseWriter, r *http.Request) {
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
	var assignTicketForm schema.ValidateAssignTicket

	// Converting request body data into native golang structure
	v := r.FormValue("data")
	if err := json.Unmarshal([]byte(v), &assignTicketForm); err != nil {
		err = errors.Wrap(err, "Unable to read json schema", &errors.BadRequest)
		requestCTX.SetErr(err, 400)
		return
	}

	// Validator implements value validations for structs and individual fields based on tags
	if errs := a.Validator.Validate(&assignTicketForm); errs != nil {
		requestCTX.SetErrs(errs, 400)
		return
	}

	assignTicketForm.AssignedTo = &schema.UserModel{
		UserID: requestCTX.UserClaim.(*auth.UserClaim).ID,
		Name:   requestCTX.UserClaim.(*auth.UserClaim).Name,
		Email:  requestCTX.UserClaim.(*auth.UserClaim).Email,
	}

	//Logging request data for tracking
	userClaim, _ := json.Marshal(requestCTX.UserClaim.(*auth.UserClaim))
	a.Logger.Log().Str("request_id", requestCTX.RequestID).Str("request_status", "initiating").Str("action", "assign_ticket").Hex("request_data", []byte(v)).Hex("user_claim", userClaim).Msg("Assign Ticket request data.")

	//Calling AssignTicket function and passing assignTicketForm as parameters
	ticket, err := a.App.Ticket.AssignTicket(&assignTicketForm)
	if err != nil {
		a.Logger.Log().Str("request_id", requestCTX.RequestID).Str("action", "assign_ticket").Str("status_code", "500").Err(err).Msg("Assign Ticket error response.")
		requestCTX.SetErr(err, 500)
		return
	}

	//Logging response data for tracking
	response, _ := json.Marshal(ticket)
	a.Logger.Log().Str("request_id", requestCTX.RequestID).Str("action", "assign_ticket").Str("request_status", "responding").Hex("response_data", response).Str("status_code", "200").Msg("Assign Ticket response data.")

	requestCTX.SetAppResponse(ticket, 200)
}

// closeTicketByUser is used to close ticket by user
func (a *API) closeTicketByUser(requestCTX *handler.RequestContext, w http.ResponseWriter, r *http.Request) {
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
	var closeTicketForm schema.ValidateCloseTicket

	// Converting request body data into native golang structure
	v := r.FormValue("data")
	if err := json.Unmarshal([]byte(v), &closeTicketForm); err != nil {
		err = errors.Wrap(err, "Unable to read json schema", &errors.BadRequest)
		requestCTX.SetErr(err, 400)
		return
	}

	// Validator implements value validations for structs and individual fields based on tags
	if errs := a.Validator.Validate(&closeTicketForm); errs != nil {
		requestCTX.SetErrs(errs, 400)
		return
	}
	if closeTicketForm.ClosedBy == nil {
		requestCTX.SetErr(errors.New("User data reqiired.", &errors.BadRequest), 400)
	}
	closeTicketForm.UserTye = "user"

	//Logging request data for tracking
	userClaim, _ := json.Marshal(requestCTX.UserClaim.(*auth.UserClaim))
	a.Logger.Log().Str("request_id", requestCTX.RequestID).Str("request_status", "initiating").Str("action", "close_ticket_by_user").Hex("request_data", []byte(v)).Hex("user_claim", userClaim).Msg("Close Ticket By User request data.")

	//Calling CloseTicket function and passing closeTicketForm as parameters
	ticket, err := a.App.Ticket.CloseTicket(&closeTicketForm)
	if err != nil {
		a.Logger.Log().Str("request_id", requestCTX.RequestID).Str("action", "close_ticket_by_user").Str("status_code", "500").Err(err).Msg("Close Ticket By User error response.")
		requestCTX.SetErr(err, 500)
		return
	}

	//Logging response data for tracking
	response, _ := json.Marshal(ticket)
	a.Logger.Log().Str("request_id", requestCTX.RequestID).Str("action", "close_ticket_by_user").Str("request_status", "responding").Hex("response_data", response).Str("status_code", "200").Msg("Close Ticket By User response data.")

	requestCTX.SetAppResponse(ticket, 200)
}

// closeTicketByAgent is used to close ticket by agent
func (a *API) closeTicketByAgent(requestCTX *handler.RequestContext, w http.ResponseWriter, r *http.Request) {
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
	var closeTicketForm schema.ValidateCloseTicket

	// Converting request body data into native golang structure
	v := r.FormValue("data")
	if err := json.Unmarshal([]byte(v), &closeTicketForm); err != nil {
		err = errors.Wrap(err, "Unable to read json schema", &errors.BadRequest)
		requestCTX.SetErr(err, 400)
		return
	}

	// Validator implements value validations for structs and individual fields based on tags
	if errs := a.Validator.Validate(&closeTicketForm); errs != nil {
		requestCTX.SetErrs(errs, 400)
		return
	}
	closeTicketForm.UserTye = "agent"
	closeTicketForm.ClosedBy = &schema.UserModel{
		UserID: requestCTX.UserClaim.(*auth.UserClaim).ID,
		Name:   requestCTX.UserClaim.(*auth.UserClaim).Name,
		Email:  requestCTX.UserClaim.(*auth.UserClaim).Email,
	}

	//Logging request data for tracking
	userClaim, _ := json.Marshal(requestCTX.UserClaim.(*auth.UserClaim))
	a.Logger.Log().Str("request_id", requestCTX.RequestID).Str("request_status", "initiating").Str("action", "close_ticket_by_agent").Hex("request_data", []byte(v)).Hex("user_claim", userClaim).Msg("Close Ticket By Agent request data.")

	//Calling CloseTicket function and passing closeTicketForm as parameters
	ticket, err := a.App.Ticket.CloseTicket(&closeTicketForm)
	if err != nil {
		a.Logger.Log().Str("request_id", requestCTX.RequestID).Str("action", "close_ticket_by_agent").Str("status_code", "500").Err(err).Msg("Close Ticket By Agent error response.")
		requestCTX.SetErr(err, 500)
		return
	}

	//Logging response data for tracking
	response, _ := json.Marshal(ticket)
	a.Logger.Log().Str("request_id", requestCTX.RequestID).Str("action", "close_ticket_by_agent").Str("request_status", "responding").Hex("response_data", response).Str("status_code", "200").Msg("Close Ticket By Agent response data.")

	requestCTX.SetAppResponse(ticket, 200)
}

// conversationReplyByUser add reply to ticket by user
func (a *API) conversationReplyByUser(requestCTX *handler.RequestContext, w http.ResponseWriter, r *http.Request) {
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
	var conversationReplyForm schema.ValidateConversationReply

	// Converting request body data into native golang structure
	v := r.FormValue("data")
	if err := json.Unmarshal([]byte(v), &conversationReplyForm); err != nil {
		err = errors.Wrap(err, "Unable to read json schema", &errors.BadRequest)
		requestCTX.SetErr(err, 400)
		return
	}

	// Validator implements value validations for structs and individual fields based on tags
	if errs := a.Validator.Validate(&conversationReplyForm); errs != nil {
		requestCTX.SetErrs(errs, 400)
		return
	}

	var attachemnts []string
	for i := 0; i < conversationReplyForm.NumFile; i++ {
		// reading file from request data
		name := "file_" + strconv.Itoa(i)
		f, fn, err := r.FormFile(name)
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
			fileUrl, err := a.App.SSS.AddFileToS3(fn.Filename, a.Config.AWSConfig.UserBucket, fn.Size, buf.Bytes())
			if err != nil {
				e := errors.Wrap(err, "Failed to upload document to S3.", &errors.SomethingWentWrong)
				requestCTX.SetErr(e, 500)
				return
			}
			attachemnts = append(attachemnts, fileUrl)
		}
	}
	conversationReplyForm.Attachments = attachemnts

	if conversationReplyForm.CreatedBy == nil {
		requestCTX.SetErr(errors.New("User data reqiired.", &errors.BadRequest), 400)
	}
	conversationReplyForm.UserTye = "user"

	//Logging request data for tracking
	userClaim, _ := json.Marshal(requestCTX.UserClaim.(*auth.UserClaim))
	a.Logger.Log().Str("request_id", requestCTX.RequestID).Str("request_status", "initiating").Str("action", "conservation_reply_by_user").Hex("request_data", []byte(v)).Hex("user_claim", userClaim).Msg("Conversation Reply By User request data.")

	//Calling Conversation Reply By User function and passing conversationReplyForm as parameters
	conversation, err := a.App.Ticket.ConversationReply(&conversationReplyForm)
	if err != nil {
		a.Logger.Log().Str("request_id", requestCTX.RequestID).Str("action", "conservation_reply_by_user").Str("status_code", "500").Err(err).Msg("Conversation Reply By User error response.")
		requestCTX.SetErr(err, 500)
		return
	}

	//Logging response data for tracking
	response, _ := json.Marshal(conversation)
	a.Logger.Log().Str("request_id", requestCTX.RequestID).Str("action", "conservation_reply_by_user").Str("request_status", "responding").Hex("response_data", response).Str("status_code", "200").Msg("Conversation Reply By User response data.")

	requestCTX.SetAppResponse(conversation, 200)
}

// conversationReplyByAgent add reply to ticket by user
func (a *API) conversationReplyByAgent(requestCTX *handler.RequestContext, w http.ResponseWriter, r *http.Request) {
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
	var conversationReplyForm schema.ValidateConversationReply

	// Converting request body data into native golang structure
	v := r.FormValue("data")
	if err := json.Unmarshal([]byte(v), &conversationReplyForm); err != nil {
		err = errors.Wrap(err, "Unable to read json schema", &errors.BadRequest)
		requestCTX.SetErr(err, 400)
		return
	}

	// Validator implements value validations for structs and individual fields based on tags
	if errs := a.Validator.Validate(&conversationReplyForm); errs != nil {
		requestCTX.SetErrs(errs, 400)
		return
	}

	var attachemnts []string
	for i := 0; i < conversationReplyForm.NumFile; i++ {
		// reading file from request data
		name := "file_" + strconv.Itoa(i)
		f, fn, err := r.FormFile(name)
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
			fileUrl, err := a.App.SSS.AddFileToS3(fn.Filename, a.Config.AWSConfig.UserBucket, fn.Size, buf.Bytes())
			if err != nil {
				e := errors.Wrap(err, "Failed to upload document to S3.", &errors.SomethingWentWrong)
				requestCTX.SetErr(e, 500)
				return
			}
			attachemnts = append(attachemnts, fileUrl)
		}
	}
	conversationReplyForm.Attachments = attachemnts
	conversationReplyForm.UserTye = "agent"
	conversationReplyForm.CreatedBy = &schema.UserModel{
		UserID: requestCTX.UserClaim.(*auth.UserClaim).ID,
		Name:   requestCTX.UserClaim.(*auth.UserClaim).Name,
		Email:  requestCTX.UserClaim.(*auth.UserClaim).Email,
	}

	//Logging request data for tracking
	userClaim, _ := json.Marshal(requestCTX.UserClaim.(*auth.UserClaim))
	a.Logger.Log().Str("request_id", requestCTX.RequestID).Str("request_status", "initiating").Str("action", "conservation_reply_by_agent").Hex("request_data", []byte(v)).Hex("user_claim", userClaim).Msg("Conversation Reply By Agent request data.")

	//Calling Conversation Reply By Agent function and passing conversationReplyForm as parameters
	conversation, err := a.App.Ticket.ConversationReply(&conversationReplyForm)
	if err != nil {
		a.Logger.Log().Str("request_id", requestCTX.RequestID).Str("action", "conservation_reply_by_agent").Str("status_code", "500").Err(err).Msg("Conversation Reply By Agent error response.")
		requestCTX.SetErr(err, 500)
		return
	}

	//Logging response data for tracking
	response, _ := json.Marshal(conversation)
	a.Logger.Log().Str("request_id", requestCTX.RequestID).Str("action", "conservation_reply_by_agent").Str("request_status", "responding").Hex("response_data", response).Str("status_code", "200").Msg("Conversation Reply By Agent response data.")

	requestCTX.SetAppResponse(conversation, 200)
}

// userFeedback adds feedback to ticket by user
func (a *API) userFeedback(requestCTX *handler.RequestContext, w http.ResponseWriter, r *http.Request) {
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
	var userFeedbackForm schema.ValidateUserFeedback

	// Converting request body data into native golang structure
	v := r.FormValue("data")
	if err := json.Unmarshal([]byte(v), &userFeedbackForm); err != nil {
		err = errors.Wrap(err, "Unable to read json schema", &errors.BadRequest)
		requestCTX.SetErr(err, 400)
		return
	}

	// Validator implements value validations for structs and individual fields based on tags
	if errs := a.Validator.Validate(&userFeedbackForm); errs != nil {
		requestCTX.SetErrs(errs, 400)
		return
	}

	//Logging request data for tracking
	userClaim, _ := json.Marshal(requestCTX.UserClaim.(*auth.UserClaim))
	a.Logger.Log().Str("request_id", requestCTX.RequestID).Str("request_status", "initiating").Str("action", "user_feedback").Hex("request_data", []byte(v)).Hex("user_claim", userClaim).Msg("User Feedback request data.")

	//Calling UserFeedback function and passing userFeedbackForm as parameters
	ticket, err := a.App.Ticket.UserFeedback(&userFeedbackForm)
	if err != nil {
		a.Logger.Log().Str("request_id", requestCTX.RequestID).Str("action", "user_feedback").Str("status_code", "500").Err(err).Msg("User Feedback error response.")
		requestCTX.SetErr(err, 500)
		return
	}

	//Logging response data for tracking
	response, _ := json.Marshal(ticket)
	a.Logger.Log().Str("request_id", requestCTX.RequestID).Str("action", "user_feedback").Str("request_status", "responding").Hex("response_data", response).Str("status_code", "200").Msg("User Feedback response data.")

	requestCTX.SetAppResponse(ticket, 200)
}

// replyToAllTickets performs reply to all tickets
func (a *API) replyToAllTickets(requestCTX *handler.RequestContext, w http.ResponseWriter, r *http.Request) {
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
	var replyToAllTicketsForm schema.ValidateReplyToAllTickets

	// Converting request body data into native golang structure
	v := r.FormValue("data")
	if err := json.Unmarshal([]byte(v), &replyToAllTicketsForm); err != nil {
		err = errors.Wrap(err, "Unable to read json schema", &errors.BadRequest)
		requestCTX.SetErr(err, 400)
		return
	}

	// Validator implements value validations for structs and individual fields based on tags
	if errs := a.Validator.Validate(&replyToAllTicketsForm); errs != nil {
		requestCTX.SetErrs(errs, 400)
		return
	}

	var attachemnts []string
	for i := 0; i < replyToAllTicketsForm.NumFile; i++ {
		// reading file from request data
		name := "file_" + strconv.Itoa(i)
		f, fn, err := r.FormFile(name)
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
			fileUrl, err := a.App.SSS.AddFileToS3(fn.Filename, a.Config.AWSConfig.UserBucket, fn.Size, buf.Bytes())
			if err != nil {
				e := errors.Wrap(err, "Failed to upload document to S3.", &errors.SomethingWentWrong)
				requestCTX.SetErr(e, 500)
				return
			}
			attachemnts = append(attachemnts, fileUrl)
		}
	}
	replyToAllTicketsForm.Attachments = attachemnts
	replyToAllTicketsForm.UserTye = "agent"
	replyToAllTicketsForm.CreatedBy = &schema.UserModel{
		UserID: requestCTX.UserClaim.(*auth.UserClaim).ID,
		Name:   requestCTX.UserClaim.(*auth.UserClaim).Name,
		Email:  requestCTX.UserClaim.(*auth.UserClaim).Email,
	}

	//Logging request data for tracking
	userClaim, _ := json.Marshal(requestCTX.UserClaim.(*auth.UserClaim))
	a.Logger.Log().Str("request_id", requestCTX.RequestID).Str("request_status", "initiating").Str("action", "reply_to_all_tickets").Hex("request_data", []byte(v)).Hex("user_claim", userClaim).Msg("Reply To All Tickets request data.")

	//Calling Reply To All Tickets function and passing conversationReplyForm as parameters
	conversation, err := a.App.Ticket.ReplyToAllTickets(&replyToAllTicketsForm)
	if err != nil {
		a.Logger.Log().Str("request_id", requestCTX.RequestID).Str("action", "reply_to_all_tickets").Str("status_code", "500").Err(err).Msg("Reply To All Tickets error response.")
		requestCTX.SetErr(err, 500)
		return
	}

	//Logging response data for tracking
	response, _ := json.Marshal(conversation)
	a.Logger.Log().Str("request_id", requestCTX.RequestID).Str("action", "reply_to_all_tickets").Str("request_status", "responding").Hex("response_data", response).Str("status_code", "200").Msg("Reply To All Tickets response data.")

	requestCTX.SetAppResponse(conversation, 200)
}
