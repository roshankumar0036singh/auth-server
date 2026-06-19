package service

import (
	"fmt"

	"github.com/roshankumar0036singh/auth-server/internal/repository"
)

var ErrUserNotFound = repository.ErrUserNotFound

// ErrTemplateNotFound is returned when a requested email template is not in the cache.
type ErrTemplateNotFound struct {
	Name string
}

func (e *ErrTemplateNotFound) Error() string {
	return fmt.Sprintf("email template %q not found", e.Name)
}