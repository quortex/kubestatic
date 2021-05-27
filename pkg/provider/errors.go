// Package provider contains the cloud providers related interfaces and models.
package provider

import "fmt"

// ErrorCode is an error code type
type ErrorCode string

const (
	// BadRequestError is when the user apparently made an error in the request
	BadRequestError ErrorCode = "BadRequestError"
	// ForbiddenError is when the operation is denied by the permissions
	ForbiddenError ErrorCode = "ForbiddenError"
	// NotFoundError is when the requested resource does not exist
	NotFoundError ErrorCode = "NotFoundError"
	// ConflictError indicates that the request could not be processed because of conflict in the current state of the resource
	ConflictError ErrorCode = "ConflictError"
	// InternalError is when there was an unexpected error in the server
	InternalError ErrorCode = "InternalError"
)

// Error is the error type used internally by the backend
type Error struct {
	Code ErrorCode
	Msg  string
}

func (e *Error) Error() string {
	return fmt.Sprintf("Error %s - %s", e.Code, e.Msg)
}
