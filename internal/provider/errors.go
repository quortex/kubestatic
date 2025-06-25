// Package provider contains the cloud providers related interfaces and models.
package provider

import (
	"fmt"
)

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
	// RulesPerSecurityGroupLimitExceededError is when the request could not be processed because of a limit exceeded
	RulesPerSecurityGroupLimitExceededError ErrorCode = "RulesPerSecurityGroupLimitExceeded"
	// AddressLimitExceededError is when the request could not be processed because of a limit exceeded
	AddressLimitExceededError ErrorCode = "AddressLimitExceeded"
	// InternalError is when there was an unexpected error in the server
	InternalError ErrorCode = "InternalError"
	// InvalidAssociationIDNotFound is when the association ID does not exist
	InvalidAssociationIDNotFound ErrorCode = "InvalidAssociationIDNotFound"
)

// Error is the error type used internally by the backend
type Error struct {
	Code ErrorCode
	Msg  string
}

func (e *Error) Error() string {
	return fmt.Sprintf("Error %s - %s", e.Code, e.Msg)
}

// IsErrBadRequest returns if error is kind BadRequestError
func IsErrBadRequest(err error) bool {
	if e, ok := err.(*Error); ok {
		return e.Code == BadRequestError
	}
	return false
}

// IsErrForbidden returns if error is kind ForbiddenError
func IsErrForbidden(err error) bool {
	if e, ok := err.(*Error); ok {
		return e.Code == ForbiddenError
	}
	return false
}

// IsErrNotFound returns if error is kind NotFoundError
func IsErrNotFound(err error) bool {
	if e, ok := err.(*Error); ok {
		return e.Code == NotFoundError
	}
	return false
}

// IsErrConflict returns if error is kind ConflictError
func IsErrConflict(err error) bool {
	if e, ok := err.(*Error); ok {
		return e.Code == ConflictError
	}
	return false
}

// IsErrInternal returns if error is kind InternalError
func IsErrInternal(err error) bool {
	if e, ok := err.(*Error); ok {
		return e.Code == InternalError
	}
	return false
}

// IsErrRulesPerSecurityGroupLimitExceeded returns if error is kind InternalError
func IsErrRulesPerSecurityGroupLimitExceeded(err error) bool {
	if e, ok := err.(*Error); ok {
		return e.Code == RulesPerSecurityGroupLimitExceededError
	}
	return false
}

// IsErrInvalidAssociationIDNotFound returns if error is kind InvalidAssociationIDNotFound
func IsErrInvalidAssociationIDNotFound(err error) bool {
	if e, ok := err.(*Error); ok {
		return e.Code == InvalidAssociationIDNotFound
	}
	return false
}

// IsErrAddressLimitExceeded returns if error is kind AddressLimitExceededError
func IsErrAddressLimitExceeded(err error) bool {
	if e, ok := err.(*Error); ok {
		return e.Code == AddressLimitExceededError
	}
	return false
}
