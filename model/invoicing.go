package model

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Sample represents model for creating a database model structure
type Sample struct {
	ID              *primitive.ObjectID `json:"_id" bson:"_id,omitempty"`
	ClientID        primitive.ObjectID  `json:"client_id" bson:"client_id,omitempty"`
	ClientName      string              `json:"client_name" bson:"client_name,omitempty"`
	BillCode        string              `json:"bill_code" bson:"bill_code,omitempty"`
	BillDescription string              `json:"bill_description" bson:"bill_description,omitempty"`
	BillType        string              `json:"bill_type" bson:"bill_type,omitempty"`
	BillPrice       float32             `json:"bill_price" bson:"bill_price,omitempty"`
	AddedBy         string              `json:"added_by,omitempty" bson:"added_by,omitempty"`
	CreatedAt       *time.Time          `json:"created_at,omitempty" bson:"created_at,omitempty"`
	Action          string              `json:"action,omitempty" bson:"action,omitempty"`
}
