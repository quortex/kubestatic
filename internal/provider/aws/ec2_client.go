// Package aws contains the provider implementation for AWS.
package aws

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

type ec2Client interface {
	DescribeInstances(
		ctx context.Context,
		input *ec2.DescribeInstancesInput,
		opts ...func(*ec2.Options),
	) (*ec2.DescribeInstancesOutput, error)
	DescribeAddresses(
		ctx context.Context,
		params *ec2.DescribeAddressesInput,
		optFns ...func(*ec2.Options),
	) (*ec2.DescribeAddressesOutput, error)
	DescribeSecurityGroups(
		ctx context.Context,
		params *ec2.DescribeSecurityGroupsInput,
		optFns ...func(*ec2.Options),
	) (*ec2.DescribeSecurityGroupsOutput, error)
	DescribeNetworkInterfaces(
		ctx context.Context,
		params *ec2.DescribeNetworkInterfacesInput,
		optFns ...func(*ec2.Options),
	) (*ec2.DescribeNetworkInterfacesOutput, error)
	CreateSecurityGroup(
		ctx context.Context,
		params *ec2.CreateSecurityGroupInput,
		optFns ...func(*ec2.Options),
	) (*ec2.CreateSecurityGroupOutput, error)
	DeleteSecurityGroup(
		ctx context.Context,
		params *ec2.DeleteSecurityGroupInput,
		optFns ...func(*ec2.Options),
	) (*ec2.DeleteSecurityGroupOutput, error)
	AuthorizeSecurityGroupIngress(
		ctx context.Context,
		params *ec2.AuthorizeSecurityGroupIngressInput,
		optFns ...func(*ec2.Options),
	) (*ec2.AuthorizeSecurityGroupIngressOutput, error)
	RevokeSecurityGroupIngress(
		ctx context.Context,
		params *ec2.RevokeSecurityGroupIngressInput,
		optFns ...func(*ec2.Options),
	) (*ec2.RevokeSecurityGroupIngressOutput, error)
	AuthorizeSecurityGroupEgress(
		ctx context.Context,
		params *ec2.AuthorizeSecurityGroupEgressInput,
		optFns ...func(*ec2.Options),
	) (*ec2.AuthorizeSecurityGroupEgressOutput, error)
	RevokeSecurityGroupEgress(
		ctx context.Context,
		params *ec2.RevokeSecurityGroupEgressInput,
		optFns ...func(*ec2.Options),
	) (*ec2.RevokeSecurityGroupEgressOutput, error)
	AllocateAddress(
		ctx context.Context,
		params *ec2.AllocateAddressInput,
		optFns ...func(*ec2.Options)) (*ec2.AllocateAddressOutput, error)
	AssociateAddress(
		ctx context.Context,
		params *ec2.AssociateAddressInput,
		optFns ...func(*ec2.Options),
	) (*ec2.AssociateAddressOutput, error)
	DisassociateAddress(
		ctx context.Context,
		params *ec2.DisassociateAddressInput,
		optFns ...func(*ec2.Options),
	) (*ec2.DisassociateAddressOutput, error)
	ReleaseAddress(
		ctx context.Context,
		params *ec2.ReleaseAddressInput,
		optFns ...func(*ec2.Options),
	) (*ec2.ReleaseAddressOutput, error)
	ModifyNetworkInterfaceAttribute(
		ctx context.Context,
		params *ec2.ModifyNetworkInterfaceAttributeInput,
		optFns ...func(*ec2.Options),
	) (*ec2.ModifyNetworkInterfaceAttributeOutput, error)
}
