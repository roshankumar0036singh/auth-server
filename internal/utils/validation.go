package utils

import (
	"errors"
	"unicode"
	"strings"
)

// ValidatePassword checks if the password meets complexity requirements
func ValidatePassword(password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters long")
	}

	var (
		hasUpper   bool
		hasLower   bool
		hasNumber  bool
		hasSpecial bool
	)

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	if !hasUpper {
		return errors.New("password must contain at least one uppercase letter")
	}
	if !hasLower {
		return errors.New("password must contain at least one lowercase letter")
	}
	if !hasNumber {
		return errors.New("password must contain at least one number")
	}
	if !hasSpecial {
		return errors.New("password must contain at least one special character")
	}

	return nil
}

// ValidateEmail performs a lightweight structural email check.
func ValidateEmail(email string) error {
	if len(email) < 3 || len(email) > 254 {
		return errors.New("email length must be between 3 and 254 characters")
	}
	at := strings.LastIndex(email, "@")
	if at < 1 || at == len(email)-1 {
		return errors.New("email must contain an @ with non-empty local and domain parts")
	}
	domain := email[at+1:]
	if strings.Contains(domain, "@") || strings.Contains(domain, " ") {
		return errors.New("email domain is malformed")
	}
	if !strings.Contains(domain, ".") {
		return errors.New("email domain must contain a dot")
	}
	return nil
}
