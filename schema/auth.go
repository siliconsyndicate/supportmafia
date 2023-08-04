package schema

import (
	"supportmafia/model"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type VerifyToken struct {
	AccessToken string             `json:"access_token" validate:"required"`
	Resource    string             `json:"resource" validate:"required"`
	Path        string             `json:"path" validate:"required"`
	Method      string             `json:"method" validate:"required"`
	PlatformID  string             `json:"platform_id" validate:"required"`
	ServiceID   primitive.ObjectID `json:"service_id" validate:"required"`
}

type RefreshToken struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
	RedirectUrl  string `json:"redirect_url" validate:"required"`
}

type LoginResponse struct {
	RedirectUrl  string      `json:"redirect_url" validate:"required"`
	AccessToken  string      `json:"access_token" validate:"required"`
	RefreshToken string      `json:"refresh_token" validate:"required"`
	User         *model.User `json:"user" validate:"required"`
}

type ValidateLeadDetails struct {
	ID                     string `json:"_id"`
	Name                   string `json:"name"`
	Email                  string `json:"email"`
	CountryCode            string `json:"country_code"`
	Phone                  string `json:"phone"`
	Message                string `json:"message"`
	NumberOfWarehouseUsers string `json:"no_of_warehouse_users"`
	NumberOfClients        string `json:"no_of_clients"`
}
