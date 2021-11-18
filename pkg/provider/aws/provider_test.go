// Package aws contains the provider implementation for AWS.
package aws

import (
	"context"
	"fmt"
	"testing"
)

func TestCreateAddress(t *testing.T) {
	pvd, err := NewProvider()
	if err != nil {
		t.Error(err)
	}

	addr, err := pvd.CreateAddress(context.Background())
	if err != nil {
		t.Error(err)
	}

	fmt.Printf("address is %v", addr)
}
