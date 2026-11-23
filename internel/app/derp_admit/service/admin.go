package service

import "errors"

// Sentinel errors admin handlers map to HTTP status codes.
var (
	ErrAdminNotFound = errors.New("not found")
	ErrAdminConflict = errors.New("conflict")
	ErrAdminInvalid  = errors.New("invalid")
)
