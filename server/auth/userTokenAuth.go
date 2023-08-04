package auth

import (
	"encoding/json"
	"fmt"
	"supportmafia/server/config"
	"time"

	"github.com/dgrijalva/jwt-go"
	errors "github.com/vasupal1996/goerror"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// TokenAuthentication contains authentication related attributes and methods
type TokenAuthentication struct {
	Session SessionAuth
	Config  *config.TokenAuthConfig
	User    *UserAuth
}

// NewTokenAuthentication returns new instance of TokenAuthentication
func NewTokenAuthentication(c *config.TokenAuthConfig, s SessionAuth) *TokenAuthentication {
	return &TokenAuthentication{Config: c, Session: s}
}

// UserAuth contains encoded token info and user info
type UserAuth struct {
	UserClaim *UserClaim
	JWTToken  JWTToken
}

// UserClaim contains fields related to User model to be added in JWT Claims
type UserClaim struct {
	ID             primitive.ObjectID   `json:"_id,omitempty" bson:"_id,omitempty"`
	Gender         string               `json:"gender,omitempty" bson:"gender,omitempty"`
	Image          string               `json:"image,omitempty" bson:"image,omitempty"`
	Session        []UserSessionDetails `json:"session,omitempty" bson:"session,omitempty"`
	Name           string               `json:"name,omitempty" bson:"name,omitempty"`
	Email          string               `json:"email,omitempty" bson:"email,omitempty"`
	PhoneNumber    string               `json:"phone_number,omitempty" bson:"phone_number,omitempty"`
	OrganizationID *primitive.ObjectID  `json:"organization_id,omitempty" bson:"organization_id,omitempty"`
	EmailVerified  bool                 `json:"email_verified,omitempty" bson:"email_verified,omitempty"`
	CreatedAt      *time.Time           `json:"created_at,omitempty" bson:"created_at,omitempty"`
	CreatedBy      *UserModel           `json:"created_by,omitempty" bson:"created_by,omitempty"`
	UpdatedAt      *time.Time           `json:"updated_at,omitempty" bson:"updated_at,omitempty"`

	Teams    []primitive.ObjectID `json:"teams,omitempty" bson:"teams,omitempty"`
	Timezone string               `json:"timezone,omitempty" bson:"timezone,omitempty"`

	IsDeactivated      bool       `json:"is_deactivated,omitempty" bson:"is_deactivated,omitempty"`
	DeactivatedAt      *time.Time `json:"deactivated_at,omitempty" bson:"deactivated_at,omitempty"`
	DeactivatedBy      string     `json:"deactivated_by,omitempty" bson:"deactivated_by,omitempty"`
	DeactivationReason string     `json:"deactivation_reason,omitempty" bson:"deactivation_reason,omitempty"`

	Access    []string `json:"access,omitempty" bson:"access,omitempty"`
	SessionID string   `json:"session_id,omitempty" bson:"session_id,omitempty"`
	TokenID   string   `json:"token_id,omitempty" bson:"token_id,omitempty"`
	Expiry    int64    `json:"exp,omitempty" bson:"exp,omitempty"`
	jwt.StandardClaims
}

// UserOrganization contans reference to Organization
type UserOrganization struct {
	OrganizationID primitive.ObjectID `json:"_id"`
	Role           string             `json:"role" `
	AddedAt        *time.Time         `json:"added_at"`
}

// UserSessionDetails contains details about User Session
type UserSessionDetails struct {
	SessionID string     `json:"session_id,omitempty"`
	UserAgent string     `json:"user_agent,omitempty"`
	Platform  string     `json:"platform,omitempty"`
	Token     string     `json:"token,omitempty"`
	CreatedAt *time.Time `json:"created_at,omitempty"`
}

// CreatedBy contains info about user who is creating something
type UserModel struct {
	UserID      primitive.ObjectID `json:"user_id,omitempty" bson:"user_id,omitempty"`
	PhoneNumber string             `json:"phone_number,omitempty" bson:"phone_number,omitempty"`
	Name        string             `json:"name,omitempty" bson:"name,omitempty"`
	Email       string             `json:"email,omitempty" bson:"email,omitempty"`
}

// GetJWTToken return jwt.Token with claimInfo from user claim fields
func (uc *UserClaim) GetJWTToken() *jwt.Token {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, uc)
	return token
}

// ToJSON := converting struct to json
func (uc *UserClaim) ToJSON() string {
	json, _ := json.Marshal(uc)
	return string(json)
}

// IsGranted checks user access control permissions
func (uc *UserClaim) IsGranted(str string) bool {
	if len(uc.Access) > 0 {
		if str != "" {
			for _, access := range uc.Access {
				if access == str {
					return true
				}
			}
			return false
		}
	}
	return true
}

// SignToken sign and encodes jwt.Token as a string
func (t *TokenAuthentication) SignToken(claim Claim) (string, error) {
	userClaim := claim.(*UserClaim)
	if t.Config.JWTExpiresAt != 0 {
		expirationTime := time.Now().Add(time.Duration(t.Config.JWTExpiresAt) * time.Minute)
		userClaim.StandardClaims.ExpiresAt = expirationTime.Unix()
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, userClaim)
	tokenString, _ := token.SignedString([]byte(t.Config.JWTSignKey))
	return tokenString, nil
}

// VerifyToken first verifies the authenticity of the jwt token string and then parse the token string into struct
func (t *TokenAuthentication) VerifyToken(tokenString string) (Claim, string, error) {
	uc := UserClaim{}
	token, err := jwt.ParseWithClaims(tokenString, &uc, func(token *jwt.Token) (interface{}, error) {
		return []byte(t.Config.JWTSignKey), nil
	})
	if err != nil {
		return nil, "", errors.Wrap(err, "Invalid token, failed to parse token", &errors.PermissionDenied)
	}

	if !token.Valid {
		return nil, "", errors.Wrap(err, "Invalid token", &errors.PermissionDenied)
	}
	// Get session data from redis using session_id
	var session_data *UserClaim
	session_data_str, err := t.Session.GetToken(uc.SessionID)
	if err != nil {
		return nil, "", errors.Wrap(err, "session not found", &errors.PermissionDenied)
	}

	err = json.Unmarshal([]byte(session_data_str), &session_data)
	if err != nil {
		return nil, "", errors.Wrap(err, "cannot unmarshal session data", &errors.SomethingWentWrong)
	}

	return session_data, uc.SessionID, nil
}

// GetClaim returns token claim
func (t *TokenAuthentication) GetClaim() Claim {
	return t.User.UserClaim
}

// SetClaim sets token claim
func (t *TokenAuthentication) SetClaim(uc Claim) {
	if uc == nil {
		return
	}
	t.User = &UserAuth{
		UserClaim: uc.(interface{}).(*UserClaim),
	}
}

func (t *TokenAuthentication) GetSessionID(tokenString string) (string, error) {
	uc := UserClaim{}
	newJwt := new(jwt.Parser)
	fmt.Println(tokenString)
	_, _, err := newJwt.ParseUnverified(tokenString, &uc)

	if err != nil {
		return "", errors.Wrap(err, "Invalid token, failed to parse token", &errors.PermissionDenied)
	}

	return uc.SessionID, nil
}
