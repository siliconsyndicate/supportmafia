package model

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Ticket struct {
	ID          *primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	Topic       string              `json:"topic,omitempty" bson:"topic,omitempty"`
	Description string              `json:"description,omitempty" bson:"description,omitempty"`
	Attachments []string            `json:"attachments,omitempty" bson:"attachments,omitempty"` //urls
	Category    string              `json:"category,omitempty" bson:"category,omitempty"`       //bug, query
	Status      string              `json:"status,omitempty" bson:"status,omitempty"`           //open, resolving, closed
	Priority    string              `json:"priority,omitempty" bson:"priority,omitempty"`       //low, medium, high, new
	AssignedTo  *UserModel          `json:"assigned_to,omitempty" bson:"assigned_to,omitempty"`
	AssignedAt  *time.Time          `json:"assigned_at,omitempty" bson:"assigned_at,omitempty"`
	Feedback    *Feedback           `json:"feedback,omitempty" bson:"feedback,omitempty"`
	CreatedBy   *UserModel          `json:"created_by,omitempty" bson:"created_by,omitempty"`
	CreatedAt   *time.Time          `json:"created_at,omitempty" bson:"created_at,omitempty"`
	IsOpen      bool                `json:"is_open,omitempty" bson:"is_open,omitempty"`
	IsResolved  bool                `json:"is_resolved,omitempty" bson:"is_resolved,omitempty"`
	ResolvedBy  *UserModel          `json:"resolved_by,omitempty" bson:"resolved_by,omitempty"`
	ResolvedAt  *time.Time          `json:"resolved_at,omitempty" bson:"resolved_at,omitempty"`
	IsClosed    bool                `json:"is_closed,omitempty" bson:"is_closed,omitempty"`
	ClosedBy    *UserModel          `json:"closed_by,omitempty" bson:"closed_by,omitempty"`
	ClosedAt    *time.Time          `json:"closed_at,omitempty" bson:"closed_at,omitempty"`
	Traces      []Trace             `json:"traces,omitempty" bson:"traces,omitempty"`
	Platform    string              `json:"platform,omitempty" bson:"platform,omitempty"`
}

type Trace struct {
	Key   string `json:"key,omitempty" bson:"key,omitempty"`
	Value string `json:"value,omitempty" bson:"value,omitempty"`
}

type Feedback struct {
	Rating      int    `json:"rating,omitempty" bson:"rating,omitempty"`
	Description string `json:"description,omitempty" bson:"description,omitempty"`
}

type Conversation struct {
	ID          *primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	TicketID    *primitive.ObjectID `json:"ticket_id,omitempty" bson:"ticket_id,omitempty"`
	Message     string              `json:"message,omitempty" bson:"message,omitempty"`
	Attachments []string            `json:"attachments,omitempty" bson:"attachments,omitempty"` //urls
	CreatedAt   *time.Time          `json:"created_at,omitempty" bson:"created_at,omitempty"`
	CreatedBy   *UserModel          `json:"created_by,omitempty" bson:"created_by,omitempty"`
}
