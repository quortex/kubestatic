// Package converter provides conversion methods for AWS models.
package converter

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/quortex/kubestatic/internal/provider"
)

// DecodeAddress converts an ec2 Address to an Address.
func DecodeAddress(data *ec2.Address) *provider.Address {
	if data == nil {
		return nil
	}

	return &provider.Address{
		AddressID:     aws.StringValue(data.AllocationId),
		AssociationID: data.AssociationId,
		PublicIP:      aws.StringValue(data.PublicIp),
	}
}
