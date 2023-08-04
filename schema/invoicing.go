package schema

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// ValidatePricingLineItems validates Pricing line items for invoicing
type ValidatePricingLineItems struct {
	ClientID        primitive.ObjectID `json:"client_id" validate:"required"`
	ClientName      string             `json:"client_name"`
	BillCode        string             `json:"bill_code" validate:"required"`
	BillDescription string             `json:"bill_description" validate:"required"`
	BillType        string             `json:"bill_type" validate:"required"`
	BillPrice       float32            `json:"bill_price" validate:"required"`
	Username        string             `json:"username"`
	Action          string             `json:"action" validate:"required"`
	RefNo           string             `json:"ref_no"`
}
