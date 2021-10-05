// Package aws contains the provider implementation for AWS.
package aws

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"path"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	corev1 "k8s.io/api/core/v1"

	"quortex.io/kubestatic/pkg/provider"
	"quortex.io/kubestatic/pkg/provider/aws/converter"
)

const (
	instanceMetadataEndpoint = "http://169.254.169.254/latest/meta-data"
)

// The VPC identifier
// Automatically retrieved with GetVPCID function.
// For run outside of the cluster, can be set through linker flag, e.g.
// go build -ldflags "-X quortex.io/kubestatic/pkg/provider/aws.vpcID=$VPC_ID" -a -o manager main.go
var vpcID string

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

	// Get vpc ID from the running instance
	_, err = retrieveVPCID()
	if err != nil {
		panic(err)
	}

	return &awsProvider{
		ec2: ec2.New(session),
	}
}

func retrieveInstanceNetworkInterfaceMacAddress() (string, error) {
	res, err := http.Get(instanceMetadataEndpoint + "/mac")
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

func retrieveVPCID() (string, error) {
	if vpcID != "" {
		return vpcID, nil
	}
	mac, err := retrieveInstanceNetworkInterfaceMacAddress()
	if err != nil {
		return "", err
	}

	res, err := http.Get(fmt.Sprintf(instanceMetadataEndpoint + "/network/interfaces/macs/" + mac + "/vpc-id"))
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
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

func (p *awsProvider) GetFirewallRule(ctx context.Context, firewallRuleID string) (*provider.FirewallRule, error) {
	res, err := p.ec2.DescribeSecurityGroups(&ec2.DescribeSecurityGroupsInput{
		GroupIds: aws.StringSlice([]string{firewallRuleID}),
	})

	if err != nil {
		return nil, converter.DecodeEC2Error("failed to get security group", err)
	}

	if len(res.SecurityGroups) == 0 {
		return nil, &provider.Error{
			Code: provider.NotFoundError,
			Msg:  fmt.Sprintf("failed to get security group: security group with group-id %s not found", firewallRuleID),
		}
	}

	return converter.DecodeSecurityGroup(res.SecurityGroups[0]), nil
}

func (p *awsProvider) CreateFirewallRule(ctx context.Context, req provider.CreateFirewallRuleRequest) (*provider.FirewallRule, error) {
	res, err := p.ec2.CreateSecurityGroup(&ec2.CreateSecurityGroupInput{
		Description: aws.String(req.Description),
		GroupName:   aws.String(req.Name),
		VpcId:       aws.String(vpcID),
	})

	if err != nil {
		return nil, converter.DecodeEC2Error("failed to create security group", err)
	}

	if res.GroupId != nil && req.IPPermission != nil {
		switch req.Direction {
		case provider.DirectionIngress:
			return p.authorizeSecurityGroupIngress(ctx, *res.GroupId, *req.IPPermission)
		case provider.DirectionEgress:
			return p.authorizeSecurityGroupEgress(ctx, *res.GroupId, *req.IPPermission)
		}
	}

	return p.GetFirewallRule(ctx, aws.StringValue(res.GroupId))
}

func (p *awsProvider) DeleteFirewallRule(ctx context.Context, firewallRuleID string) error {
	_, err := p.ec2.DeleteSecurityGroup(&ec2.DeleteSecurityGroupInput{
		GroupId: aws.String(firewallRuleID),
	})

	if err != nil {
		return converter.DecodeEC2Error("failed to delete security group", err)
	}

	return nil
}

func (p *awsProvider) authorizeSecurityGroupIngress(ctx context.Context, firewallRuleID string, req provider.IPPermission) (*provider.FirewallRule, error) {
	_, err := p.ec2.AuthorizeSecurityGroupIngress(&ec2.AuthorizeSecurityGroupIngressInput{
		GroupId: aws.String(firewallRuleID),
		IpPermissions: []*ec2.IpPermission{
			converter.EncodeIPPermission(req),
		},
	})

	if err != nil {
		return nil, converter.DecodeEC2Error("failed to authorize security group ingress permission", err)
	}

	return p.GetFirewallRule(ctx, firewallRuleID)
}

func (p *awsProvider) revokeSecurityGroupIngress(ctx context.Context, firewallRuleID string, req provider.IPPermission) error {
	_, err := p.ec2.RevokeSecurityGroupIngress(&ec2.RevokeSecurityGroupIngressInput{
		GroupId: aws.String(firewallRuleID),
		IpPermissions: []*ec2.IpPermission{
			converter.EncodeIPPermission(req),
		},
	})

	if err != nil {
		return converter.DecodeEC2Error("failed to revoke security group ingress permission", err)
	}

	return nil
}

func (p *awsProvider) authorizeSecurityGroupEgress(ctx context.Context, firewallRuleID string, req provider.IPPermission) (*provider.FirewallRule, error) {
	_, err := p.ec2.AuthorizeSecurityGroupEgress(&ec2.AuthorizeSecurityGroupEgressInput{
		GroupId: aws.String(firewallRuleID),
		IpPermissions: []*ec2.IpPermission{
			converter.EncodeIPPermission(req),
		},
	})

	if err != nil {
		return nil, converter.DecodeEC2Error("failed to authorize security group egress permission", err)
	}

	return p.GetFirewallRule(ctx, firewallRuleID)
}

func (p *awsProvider) revokeSecurityGroupEgress(ctx context.Context, firewallRuleID string, req provider.IPPermission) error {
	_, err := p.ec2.RevokeSecurityGroupEgress(&ec2.RevokeSecurityGroupEgressInput{
		GroupId: aws.String(firewallRuleID),
		IpPermissions: []*ec2.IpPermission{
			converter.EncodeIPPermission(req),
		},
	})

	if err != nil {
		return converter.DecodeEC2Error("failed to revoke security group egress permission", err)
	}

	return nil
}

func (p *awsProvider) AssociateFirewallRule(ctx context.Context, req provider.AssociateFirewallRuleRequest) error {
	res, err := p.ec2.DescribeNetworkInterfaces(&ec2.DescribeNetworkInterfacesInput{
		NetworkInterfaceIds: aws.StringSlice([]string{req.NetworkInterfaceID}),
	})

	if err != nil {
		return err
	}

	if len(res.NetworkInterfaces) == 0 {
		return &provider.Error{
			Code: provider.NotFoundError,
			Msg:  fmt.Sprintf("failed to associate security group: network interface with id %s not found", req.NetworkInterfaceID),
		}
	}

	networkInterface := res.NetworkInterfaces[0]
	groups := []*string{}
	for _, e := range networkInterface.Groups {
		if req.FirewallRuleID != *e.GroupId {
			groups = append(groups, e.GroupId)
		}
	}
	groups = append(groups, aws.String(req.FirewallRuleID))

	_, err = p.ec2.ModifyNetworkInterfaceAttribute(&ec2.ModifyNetworkInterfaceAttributeInput{
		Groups:             groups,
		NetworkInterfaceId: aws.String(req.NetworkInterfaceID),
	})

	return err
}

func (p *awsProvider) DisassociateFirewallRule(ctx context.Context, req provider.AssociateFirewallRuleRequest) error {
	res, err := p.ec2.DescribeNetworkInterfaces(&ec2.DescribeNetworkInterfacesInput{
		NetworkInterfaceIds: aws.StringSlice([]string{req.NetworkInterfaceID}),
	})

	if err != nil {
		return err
	}

	if len(res.NetworkInterfaces) == 0 {
		return &provider.Error{
			Code: provider.NotFoundError,
			Msg:  fmt.Sprintf("failed to disassociate security group: network interface with id %s not found", req.NetworkInterfaceID),
		}
	}

	networkInterface := res.NetworkInterfaces[0]
	groups := []*string{}
	for _, e := range networkInterface.Groups {
		if req.FirewallRuleID != aws.StringValue(e.GroupId) {
			groups = append(groups, e.GroupId)
		}
	}

	_, err = p.ec2.ModifyNetworkInterfaceAttribute(&ec2.ModifyNetworkInterfaceAttributeInput{
		Groups:             groups,
		NetworkInterfaceId: aws.String(req.NetworkInterfaceID),
	})

	return err
}
