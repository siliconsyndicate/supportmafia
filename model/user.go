package model

import (
	"time"

	auth "supportmafia/server/auth"
	"supportmafia/util"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// User represents user in mongodb
type User struct {
	ID                  *primitive.ObjectID  `json:"_id,omitempty" bson:"_id,omitempty"`
	Gender              string               `json:"gender,omitempty" bson:"gender,omitempty"`
	Image               string               `json:"image,omitempty" bson:"image,omitempty"`
	Sessions            []UserSessionDetails `json:"sessions,omitempty" bson:"sessions,omitempty"`
	Password            string               `json:"password,omitempty" bson:"password,omitempty"`
	PasswordResetCode   string               `json:"password_reset_code,omitempty" bson:"password_reset_code,omitempty"`
	ResetCodeExpiration *time.Time           `json:"reset_code_expiration,omitempty" bson:"reset_code_expiration,omitempty"`
	ConfirmationCode    string               `json:"confirmation_code,omitempty" bson:"confirmation_code,omitempty"`
	Email               string               `json:"email,omitempty" bson:"email,omitempty"`
	PhoneNumber         string               `json:"phone_number,omitempty" bson:"phone_number,omitempty"`
	Name                string               `json:"name,omitempty" bson:"name,omitempty"`
	OrganizationID      *primitive.ObjectID  `json:"organization_id,omitempty" bson:"organization_id,omitempty"`
	EmailVerifiedAt     *time.Time           `json:"email_verified_at,omitempty" bson:"email_verified_at,omitempty"`
	CreatedAt           *time.Time           `json:"created_at,omitempty" bson:"created_at,omitempty"`
	CreatedBy           *UserModel           `json:"created_by,omitempty" bson:"created_by,omitempty"`
	UpdatedAt           *time.Time           `json:"updated_at,omitempty" bson:"updated_at,omitempty"`
	IsDeactivated       bool                 `json:"is_deactivated,omitempty" bson:"is_deactivated,omitempty"`
	DeactivatedAt       *time.Time           `json:"deactivated_at,omitempty" bson:"deactivated_at,omitempty"`
	DeactivatedBy       string               `json:"deactivated_by,omitempty" bson:"deactivated_by,omitempty"`
	DeactivationReason  string               `json:"deactivation_reason,omitempty" bson:"deactivation_reason,omitempty"`
	Timezone            string               `json:"timezone,omitempty" bson:"timezone,omitempty"`
	GoogleID            string               `json:"google_id,omitempty" bson:"google_id,omitempty"`
}

// SetPassword sets hashed password string
func (u *User) SetPassword(p string) {
	u.Password, _ = util.HashPassword(p)
}

// CheckPassword checks hashed password with provided string
func (u *User) CheckPassword(password string) bool {
	isValid := util.CheckPasswordHash(password, u.Password)
	return isValid
}

// SetConfirmationCode generates a unique confirmation code
func (u *User) SetConfirmationCode(token string) {
	u.ConfirmationCode = token
}

// GetConfirmationCode returns a unique confirmation code
func (u *User) GetConfirmationCode() string {
	return u.ConfirmationCode
}

// GetConfirmationURL returns a email confirmation url
func (u *User) GetConfirmationURL() string {
	url := "/confirm-user?code=" + u.GetConfirmationCode()
	return url
}

// SetPasswordResetCode sets password_reset_code
func (u *User) SetPasswordResetCode(otp string, expiry time.Time) {
	u.PasswordResetCode = otp
	u.ResetCodeExpiration = &expiry
}

// GetPasswordResetCode sets password_reset_code
func (u *User) GetPasswordResetCode() string {
	return u.PasswordResetCode
}

// GetPasswordResetURL returns a email confirmation url
func (u *User) GetPasswordResetURL() string {
	url := "/password-reset?code=" + u.PasswordResetCode
	return url
}

// SetClaim sets fields value in UserClaim struct
func (u *User) SetClaim(us *auth.UserClaim) {
	us.ID = *u.ID
	us.Email = u.Email
	us.Name = u.Name
	us.Image = u.Image
	us.PhoneNumber = u.PhoneNumber
	us.IsDeactivated = u.IsDeactivated
	us.DeactivatedAt = u.DeactivatedAt
	us.DeactivatedBy = u.DeactivatedBy
	us.DeactivationReason = u.DeactivationReason
	us.Gender = u.Gender
	us.CreatedAt = u.CreatedAt
	if u.CreatedBy != nil {
		us.CreatedBy = &auth.UserModel{
			UserID:      u.CreatedBy.UserID,
			PhoneNumber: u.CreatedBy.PhoneNumber,
			Email:       u.CreatedBy.Email,
			Name:        u.CreatedBy.Name,
		}
	}
	us.UpdatedAt = u.UpdatedAt
	if u.EmailVerifiedAt != nil {
		us.EmailVerified = true
	} else {
		us.EmailVerified = false
	}
	us.Timezone = u.Timezone
}

func (u *User) RemoveIndex(s []string, index int) []string {
	return append(s[:index], s[index+1:]...)
}

// UserWarehouse contans reference to Team
type UserWarehouse struct {
	WarehouseID primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	Alias       string             `json:"alias,omitempty" bson:"alias,omitempty"`
	Role        string             `json:"role,omitempty" bson:"role,omitempty"`
	AddedAt     *time.Time         `json:"added_at,omitempty" bson:"added_at,omitempty"`
}

// UserSessionDetails contains details about User Session
type UserSessionDetails struct {
	SessionID   string     `json:"session_id,omitempty" bson:"session_id,omitempty"`
	UserAgent   string     `json:"user_agent,omitempty" bson:"user_agent,omitempty"`
	TokenID     string     `json:"token_id,omitempty" bson:"token_id,omitempty"`
	CreatedAt   *time.Time `json:"created_at,omitempty" bson:"created_at,omitempty"`
	DeviceToken string     `json:"device_token,omitempty" bson:"device_token,omitempty"`
}

// CreatedBy contains info about user who is creating something
type UserModel struct {
	UserID      primitive.ObjectID `json:"user_id,omitempty" bson:"user_id,omitempty"`
	PhoneNumber string             `json:"phone_number,omitempty" bson:"phone_number,omitempty"`
	Name        string             `json:"name,omitempty" bson:"name,omitempty"`
	Email       string             `json:"email,omitempty" bson:"email,omitempty"`
}

type GooleUserData struct {
	GoogleID      string  `json:"id,omitempty" bson:"id,omitempty"`
	Name          string  `json:"name,omitempty" bson:"name,omitempty"`
	Image         string  `json:"picture,omitempty" bson:"picture,omitempty"`
	Email         string  `json:"email,omitempty" bson:"email,omitempty"`
	VerifiedEmail bool    `json:"verified_email,omitempty" bson:"verified_email,omitempty"`
	FamilyName    string  `json:"family_name,omitempty" bson:"family_name,omitempty"`
	GivenName     string  `json:"given_name,omitempty" bson:"given_name,omitempty"`
	Locale        string  `json:"locale,omitempty" bson:"locale,omitempty"`
	Hd            *string `json:"hd" bson:"hd"`
}
