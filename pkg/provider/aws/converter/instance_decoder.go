// Package converter provides conversion methods for AWS models.
package converter

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"quortex.io/kubestatic/pkg/provider"
)

// DecodeInstance converts an ec2 Instance to an Instance.
func DecodeInstance(data *ec2.Instance) *provider.Instance {
	if data == nil {
		return nil
	}

	return &provider.Instance{
		InstanceID:        aws.StringValue(data.InstanceId),
		NetworkInterfaces: DecodeNetworkInterfaces(data.NetworkInterfaces),
		VpcID:             aws.StringValue(data.VpcId),
	}
}

// DecodeNetworkInterface converts an ec2 InstanceNetworkInterface to a NetworkInterface.
func DecodeNetworkInterface(data *ec2.InstanceNetworkInterface) *provider.NetworkInterface {
	if data == nil {
		return nil
	}

	var publicIP *string
	if ass := data.Association; ass != nil {
		publicIP = ass.PublicIp
	}

	return &provider.NetworkInterface{
		NetworkInterfaceID: aws.StringValue(data.NetworkInterfaceId),
		PublicIP:           publicIP,
	}
}

// DecodeNetworkInterfaces converts an ec2 InstanceNetworkInterface slice to a NetworkInterface slice.
func DecodeNetworkInterfaces(data []*ec2.InstanceNetworkInterface) []*provider.NetworkInterface {
	if data == nil {
		return nil
	}

	res := make([]*provider.NetworkInterface, len(data))
	for i, e := range data {
		res[i] = DecodeNetworkInterface(e)
	}

	return res
}
