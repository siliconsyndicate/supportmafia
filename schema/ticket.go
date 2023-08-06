package schema

import "go.mongodb.org/mongo-driver/bson/primitive"

type ValidateCreateTicket struct {
	Topic       string     `json:"topic" validate:"required"`
	Description string     `json:"description" validate:"required"`
	Category    string     `json:"category" validate:"required"`
	Traces      []Trace    `json:"traces" validate:"required"`
	CreatedBy   *UserModel `json:"assigned_user" validate:"required"`
	Platform    string     `json:"platform" validate:"required"`
	Attachments []string   `json:"attachments"`
	NumFile     int        `json:"num_file"`
}

type Trace struct {
	Key   string `json:"key" validate:"required"`
	Value string `json:"value" validate:"required"`
}

type ValidateConversationReply struct {
	TicketID    *primitive.ObjectID `json:"ticket_id" validate:"required"`
	Message     string              `json:"message" validate:"required"`
	Attachments []string            `json:"attachments"`
	NumFile     int                 `json:"num_file"`
	CreatedBy   *UserModel          `json:"assigned_user"`
	UserTye     string              `json:"user_type"`
}

type ValidateCloseTicket struct {
	TicketID *primitive.ObjectID `json:"ticket_id" validate:"required"`
	ClosedBy *UserModel          `json:"assigned_user"`
	UserTye  string              `json:"user_type"`
}

type ValidatePrioritizeTicket struct {
	TicketID *primitive.ObjectID `json:"ticket_id" validate:"required"`
	Priority string              `json:"priority" validate:"required"`
}

type ValidateResolveTicket struct {
	TicketID   *primitive.ObjectID `json:"ticket_id" validate:"required"`
	ResolvedBy *UserModel          `json:"assigned_user"`
}

type ValidateAssignTicket struct {
	TicketID   *primitive.ObjectID `json:"ticket_id" validate:"required"`
	AssignedTo *UserModel          `json:"assigned_to" validate:"required"`
}

type ValidateUserFeedback struct {
	TicketID *primitive.ObjectID `json:"ticket_id" validate:"required"`
	Feedback *Feedback           `json:"feedback" validate:"required"`
}

type Feedback struct {
	Rating      int    `json:"rating" validate:"required,min=1,max=5"`
	Description string `json:"description"`
}

type ValidateReplyToAllTickets struct {
	Message     string               `json:"message" validate:"required"`
	TicketIDs   []primitive.ObjectID `json:"ticket_ids" validate:"required"`
	Attachments []string             `json:"attachments"`
	NumFile     int                  `json:"num_file"`
	CreatedBy   *UserModel           `json:"assigned_user"`
	UserTye     string               `json:"user_type"`
}
