package util

import (
	"golang.org/x/crypto/bcrypt"
)

// HashPassword returns encrypted password
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 4)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// CheckPasswordHash compare string and its hashed counterpart
func CheckPasswordHash(password, bcryptPassword string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(bcryptPassword), []byte(password))
	return err == nil
}
