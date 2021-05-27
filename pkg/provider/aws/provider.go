// Package aws contains the provider implementation for AWS.
package aws

import (
	"context"
	"fmt"
	"path"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	corev1 "k8s.io/api/core/v1"

	"quortex.io/kubestatic/pkg/provider"
	"quortex.io/kubestatic/pkg/provider/aws/converter"
)

type awsProvider struct {
	ec2 *ec2.EC2
}

// NewProvider instantiate a Provider implementation for AWS
func NewProvider() provider.Provider {
	// By default NewSession loads credentials from the shared credentials file (~/.aws/credentials)
	//
	// The Session will attempt to load configuration and credentials from the environment,
	// configuration files, and other credential sources. The order configuration is loaded in is:
	// * Environment Variables
	// * Shared Credentials file
	// * Shared Configuration file (if SharedConfig is enabled)
	// * EC2 Instance Metadata (credentials only)
	session, err := session.NewSession()
	if err != nil {
		panic(err)
	}

	return &awsProvider{
		ec2: ec2.New(session),
	}
}

func (p *awsProvider) GetInstanceID(node corev1.Node) string {
	return path.Base(node.Spec.ProviderID)
}

func (p *awsProvider) GetInstance(ctx context.Context, instanceID string) (*provider.Instance, error) {
	res, err := p.ec2.DescribeInstances(&ec2.DescribeInstancesInput{
		InstanceIds: aws.StringSlice([]string{instanceID}),
	})

	if err != nil {
		return nil, converter.DecodeEC2Error("failed to get instance", err)
	}

	if len(res.Reservations) == 0 || len(res.Reservations[0].Instances) == 0 {
		return nil, &provider.Error{
			Code: provider.NotFoundError,
			Msg:  fmt.Sprintf("failed to get instance: instance with instance-id %s not found", instanceID),
		}
	}

	return converter.DecodeInstance(res.Reservations[0].Instances[0]), nil
}

func (p *awsProvider) GetAddress(ctx context.Context, addressID string) (*provider.Address, error) {
	res, err := p.ec2.DescribeAddresses(&ec2.DescribeAddressesInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("domain"),
				Values: aws.StringSlice([]string{"vpc"}),
			},
			{
				Name:   aws.String("allocation-id"),
				Values: aws.StringSlice([]string{addressID}),
			},
		},
	})

	if err != nil {
		return nil, converter.DecodeEC2Error("failed to get address", err)
	}

	if len(res.Addresses) == 0 {
		return nil, &provider.Error{
			Code: provider.NotFoundError,
			Msg:  fmt.Sprintf("failed to get address: address with allocation-id %s not found", addressID),
		}
	}

	return converter.DecodeAddress(res.Addresses[0]), nil
}

func (p *awsProvider) CreateAddress(ctx context.Context) (*provider.Address, error) {
	res, err := p.ec2.AllocateAddress(&ec2.AllocateAddressInput{
		Domain: aws.String("vpc"),
	})

	if err != nil {
		return nil, converter.DecodeEC2Error("failed to create address", err)
	}

	return p.GetAddress(ctx, aws.StringValue(res.AllocationId))
}

func (p *awsProvider) DeleteAddress(ctx context.Context, addressID string) error {
	_, err := p.ec2.ReleaseAddress(&ec2.ReleaseAddressInput{
		AllocationId: aws.String(addressID),
	})

	if err != nil {
		return converter.DecodeEC2Error("failed to delete address", err)
	}

	return nil
}

func (p *awsProvider) AssociateAddress(ctx context.Context, req provider.AssociateAddressRequest) error {
	_, err := p.ec2.AssociateAddress(&ec2.AssociateAddressInput{
		AllocationId:       aws.String(req.AddressID),
		NetworkInterfaceId: aws.String(req.NetworkInterfaceID),
	})

	if err != nil {
		return converter.DecodeEC2Error("failed to associate address", err)
	}

	return nil
}

func (p *awsProvider) DisassociateAddress(ctx context.Context, req provider.DisassociateAddressRequest) error {
	_, err := p.ec2.DisassociateAddress(&ec2.DisassociateAddressInput{
		AssociationId: aws.String(req.AssociationID),
	})

	if err != nil {
		return converter.DecodeEC2Error("failed to disassociate address", err)
	}

	return nil
}
