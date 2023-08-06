package schema

import "go.mongodb.org/mongo-driver/bson/primitive"

// ValidateLoginForm validates json data for user sign-in
type ValidateLoginForm struct {
	Email     string `json:"email" validate:"required"`
	Password  string `json:"password" validate:"required"`
	UserAgent string
}

// ValidateSignUpForm validates json data while creating a new brand
type ValidateSignUpForm struct {
	Name            string `json:"name" validate:"required"`
	Email           string `json:"email" validate:"required,email"`
	Password        string `json:"password" validate:"required,eqfield=ConfirmPassword,gte=8"`
	ConfirmPassword string `json:"confirm_password" validate:"required"`
	Gender          string `json:"gender"`
}

// ValidateEmail validates email
type ValidateEmail struct {
	Email string `json:"email" validate:"required,email"`
}

// Validates the request for validating password reset code
type ValidatePasswordResetCode struct {
	Email string `json:"email" validate:"required"`
	Code  string `json:"code" validate:"required"`
}

// ValidateUserPasswordResetForm validates json data for password reset of logged in user
type ValidateUserPasswordResetForm struct {
	CurrentPassword string `json:"current_password" validate:"required"`
	Password        string `json:"new_password" validate:"required,eqfield=ConfirmPassword,gte=8"`
	ConfirmPassword string `json:"confirm_password" validate:"required"`
}

// ValidateAdminPasswordResetForm validates json data for password reset of users by admin
type ValidateAdminPasswordResetForm struct {
	UserID          primitive.ObjectID `json:"user_id" validate:"required"`
	Password        string             `json:"new_password" validate:"required,eqfield=ConfirmPassword,gte=8"`
	ConfirmPassword string             `json:"confirm_password" validate:"required"`
}

// ValidateDeactivateUser validates access field for user
type ValidateDeactivateUser struct {
	UserID             primitive.ObjectID `json:"user_id" validate:"required"`
	DeactivationReason string             `json:"deactivation_reason" validate:"required"`
	SetAccountStatus   int                `json:"set_account_status"`
}

// ValidatePasswordResetForm validates json data for password reset
type ValidatePasswordResetForm struct {
	Email           string `json:"email" validate:"required"`
	Code            string `json:"code" validate:"required"`
	Password        string `json:"password" validate:"required,eqfield=ConfirmPassword"`
	ConfirmPassword string `json:"confirm_password" validate:"required"`
}

// ValidateAccessProfile validates access profile for user
type ValidateAccessProfile struct {
	UserID         primitive.ObjectID `json:"user_id" validate:"required"`
	Access         string             `json:"access" validate:"required"`
	PlatformID     string             `json:"platform_id" validate:"required"`
	WarehouseID    primitive.ObjectID `json:"warehouse_id" validate:"required"`
	WarehouseName  string             `json:"warehouse_name" validate:"required"`
	OrganizationID primitive.ObjectID `json:"organization_id" validate:"required"`
	ClientID       primitive.ObjectID `json:"client_id"`
	ClientName     string             `json:"client_name"`
}

// ValidateClientsField validates clients field for user
type ValidateClientsField struct {
	UserID  primitive.ObjectID   `json:"user_id" validate:"required"`
	Clients []primitive.ObjectID `json:"clients" validate:"required"`
}

// ValidateManageConfiguredAccess validates add/remove access fields for user
type ValidateManageConfiguredAccess struct {
	UserID        primitive.ObjectID `json:"user_id" validate:"required"`
	PlatformID    string             `json:"platform_id"`
	AddedAccess   []string           `json:"added_access" validate:"required"`
	RemovedAccess []string           `json:"removed_access" validate:"required"`
}

// ValidateUserAccessPermissions validates json data for password reset of users by admin
type ValidateUserAccessPermissions struct {
	ProfileName    string           `json:"profile_name" validate:"required"`
	PlatformAccess []PlatformAccess `json:"platform_access"`
	Description    string           `json:"description" validate:"required"`
}

type PlatformAccess struct {
	PlatformID string   `json:"platform_id" validate:"required"`
	Access     []string `json:"access" validate:"required"`
}

// ValidateEditClientAccess validates client access for a particular service user
type ValidateEditClientAccess struct {
	UserID       primitive.ObjectID `json:"user_id" validate:"required"`
	PlatformID   string             `json:"platform_id" validate:"required"`
	ClientAccess []string           `json:"client_access" validate:"required"`
}

// ValidateSetPrimaryWarehouse validates client access for a particular service user
type ValidateSetPrimaryWarehouse struct {
	UserID      primitive.ObjectID `json:"user_id" validate:"required"`
	PlatformID  string             `json:"platform_id" validate:"required"`
	WarehouseID primitive.ObjectID `json:"warehouse_id" validate:"required"`
}

type ValidateEditAccessProfile struct {
	ProfileID   primitive.ObjectID `json:"profile_id" validate:"required"`
	Description string             `json:"description"`
	Access      []string           `json:"access"`
}

type ValidateEditUser struct {
	UserID *primitive.ObjectID `json:"user_id"`
	Image  string              `json:"image"`
	Name   string              `json:"name"`
}

// CreatedBy contains info about user who is creating something
type UserModel struct {
	UserID primitive.ObjectID `json:"user_id"`
	Name   string             `json:"name"`
	Email  string             `json:"email"`
}
