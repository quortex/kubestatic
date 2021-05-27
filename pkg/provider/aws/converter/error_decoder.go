// Package converter provides conversion methods for AWS models.
package converter

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws/awserr"

	"quortex.io/kubestatic/pkg/provider"
)

// DecodeEC2Error converts an ec2 specific Error to a QXError.
func DecodeEC2Error(msg string, err error) error {
	if err == nil {
		return nil
	}

	if aerr, ok := err.(awserr.Error); ok {
		switch aerr.Code() {
		case
			"InvalidAddress.NotFound",
			"InvalidAddressID.NotFound",
			"InvalidAllocationID.NotFound",
			"InvalidGroup.NotFound":
			return &provider.Error{Code: provider.NotFoundError, Msg: fmt.Sprintf("%s: %s", msg, err.Error())}
		case
			"InvalidGroup.Duplicate":
			return &provider.Error{Code: provider.ConflictError, Msg: fmt.Sprintf("%s: %s", msg, err.Error())}
		}
	}
	return DecodeCommonError(msg, err)
}

// DecodeCommonError converts an AWS common client Error to a QXError.
func DecodeCommonError(msg string, err error) error {
	if err == nil {
		return nil
	}

	msg = fmt.Sprintf("%s: %s", msg, err.Error())

	if aerr, ok := err.(awserr.Error); ok {
		switch aerr.Code() {
		case
			"AuthFailure",
			"UnauthorizedOperation",
			"OptInRequired",
			"PendingVerification":
			return &provider.Error{Code: provider.ForbiddenError, Msg: msg}
		case
			"MissingParameter",
			"InvalidParameter",
			"UnknownParameter",
			"InvalidParameterCombination",
			"InvalidParameterValue",
			"InvalidQueryParameter",
			"MalformedQueryString",
			"ValidationError":
			return &provider.Error{Code: provider.BadRequestError, Msg: msg}
		}
	}
	return &provider.Error{Code: provider.InternalError, Msg: msg}
}
