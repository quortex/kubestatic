// Package converter provides conversion methods for AWS models.
package converter

import (
	"github.com/Azure/azure-sdk-for-go/services/network/mgmt/2019-11-01/network"
	"github.com/quortex/kubestatic/pkg/provider"
)

// DecodeAddress converts an ec2 Address to an Address.
func DecodeAddress(data *network.PublicIPAddress) *provider.Address {
	if data == nil {
		return nil
	}

	return &provider.Address{
		AddressID:     *data.ResourceGUID,
		AssociationID: data.ID,
		PublicIP:      *data.IPAddress,
	}
}
