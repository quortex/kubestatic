// Package aws contains the provider implementation for AWS.
package aws

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"path"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	corev1 "k8s.io/api/core/v1"

	"github.com/quortex/kubestatic/internal/provider"
	"github.com/quortex/kubestatic/internal/provider/aws/converter"
)

const (
	// Retrieve instance metadata for AWS EC2 instance
	// https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html
	instanceMetadataEndpoint = "http://169.254.169.254/latest/meta-data"

	// IMDSv2 token related constants
	tokenEndpoint      = "http://169.254.169.254/latest/api/token"
	tokenTTLHeader     = "X-aws-ec2-metadata-token-ttl-seconds"
	tokenRequestHeader = "X-aws-ec2-metadata-token"
)

// The VPC identifier
// Automatically retrieved with GetVPCID function.
// For run outside of the cluster, can be set through linker flag, e.g.
// go build -ldflags "-X github.com/quortex/kubestatic/internalprovider/aws.vpcID=$VPC_ID" -a -o manager main.go
var vpcID string

type awsProvider struct {
	ec2 *ec2.EC2
}

// NewProvider instantiate a Provider implementation for AWS
func NewProvider() (provider.Provider, error) {
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
		return nil, err
	}

	// Get vpc ID from the running instance
	id, err := retrieveVPCID()
	if err != nil {
		return nil, err
	}
	vpcID = id

	return &awsProvider{
		ec2: ec2.New(session),
	}, nil
}

func getV2Token(client http.Client) (string, error) {
	req, err := http.NewRequest(http.MethodPut, tokenEndpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set(tokenTTLHeader, "21600")
	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = res.Body.Close() }()

	token, err := io.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	return string(token), nil
}

func retrieveInstanceMetadata(client http.Client, contextPath string, token string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, instanceMetadataEndpoint+contextPath, nil)
	if err != nil {
		return "", err
	}

	if token != "" {
		req.Header.Set(tokenRequestHeader, token)
	}
	res, err := client.Do(req)
	if err != nil {
		return "", err
	}

	defer func() { _ = res.Body.Close() }()
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

	client := http.Client{Timeout: 3 * time.Second}

	token, err := getV2Token(client)
	if err != nil {
		fmt.Printf("failed getting IMDSv2 token falling back to IMDSv1 : %s", err)
	}

	mac, err := retrieveInstanceMetadata(client, "/mac", token)
	if err != nil {
		return "", err
	}

	body, err := retrieveInstanceMetadata(client, "/network/interfaces/macs/"+mac+"/vpc-id", token)
	if err != nil {
		return "", err
	}

	return body, nil
}

func (p *awsProvider) GetInstanceID(node corev1.Node) string {
	return path.Base(node.Spec.ProviderID)
}

// Firewall rule groups are supported by AWS (EC2 SecurityGroups).
func (p *awsProvider) HasGroupedFirewallRules() bool {
	return true
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

func (p *awsProvider) getSecurityGroup(_ context.Context, firewallRuleID string) (*ec2.SecurityGroup, error) {
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

	return res.SecurityGroups[0], nil
}

func (p *awsProvider) FetchFirewallRule(ctx context.Context, firewallRuleGroupID string) error {
	_, err := p.getSecurityGroup(ctx, firewallRuleGroupID)
	if err != nil {
		return converter.DecodeEC2Error("failed to fetch security group", err)
	}
	return nil
}

func (p *awsProvider) CreateFirewallRule(ctx context.Context, req provider.CreateFirewallRuleRequest) (string, error) {
	panic("unimplemented method for AWS: CreateFirewallRule, use CreateFirewallRuleGroup instead")
}

func (p *awsProvider) CreateFirewallRuleGroup(ctx context.Context, req provider.CreateFirewallRuleGroupRequest) (string, error) {
	res, err := p.ec2.CreateSecurityGroup(&ec2.CreateSecurityGroupInput{
		Description: aws.String(req.Description),
		GroupName:   aws.String(req.Name),
		VpcId:       aws.String(vpcID),
	})
	if err != nil {
		return "", converter.DecodeEC2Error("failed to create security group", err)
	}

	return p.UpdateFirewallRuleGroup(ctx, provider.UpdateFirewallRuleGroupRequest{
		FirewallRuleGroupID: *res.GroupId,
		FirewallRules:       req.FirewallRules,
	})
}

func (p *awsProvider) UpdateFirewallRule(ctx context.Context, req provider.UpdateFirewallRuleRequest) (*provider.FirewallRule, error) {
	panic("unimplemented method for AWS: UpdateFirewallRule, use UpdateFirewallRuleGroup instead")
}

func (p *awsProvider) UpdateFirewallRuleGroup(ctx context.Context, req provider.UpdateFirewallRuleGroupRequest) (string, error) {
	sg, err := p.getSecurityGroup(ctx, req.FirewallRuleGroupID)
	if err != nil {
		return "", converter.DecodeEC2Error("failed to get security group", err)
	}

	// Apply Ingress permissions reconciliation
	if err := provider.ReconcilePermissions(
		ctx,
		req.FirewallRuleGroupID,
		p.authorizeSecurityGroupIngress,
		p.revokeSecurityGroupIngress,
		provider.GetIngressIPPermissions(req.FirewallRules),
		converter.DecodeIpPermissions(sg.IpPermissions),
	); err != nil {
		return "", converter.DecodeEC2Error("failed to apply security group ingress permissions", err)
	}
	// Apply Egress permissions reconciliation
	if err := provider.ReconcilePermissions(
		ctx,
		req.FirewallRuleGroupID,
		p.authorizeSecurityGroupEgress,
		p.revokeSecurityGroupEgress,
		provider.GetEgressIPPermissions(req.FirewallRules),
		converter.DecodeIpPermissions(sg.IpPermissionsEgress),
	); err != nil {
		return "", converter.DecodeEC2Error("failed to apply security group egress permissions", err)
	}

	return req.FirewallRuleGroupID, nil
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

func (p *awsProvider) authorizeSecurityGroupIngress(ctx context.Context, firewallRuleID string, req provider.IPPermission) error {
	_, err := p.ec2.AuthorizeSecurityGroupIngress(&ec2.AuthorizeSecurityGroupIngressInput{
		GroupId: aws.String(firewallRuleID),
		IpPermissions: []*ec2.IpPermission{
			converter.EncodeIPPermission(req),
		},
	})
	if err != nil {
		return converter.DecodeEC2Error("failed to authorize security group ingress permission", err)
	}

	return nil
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

func (p *awsProvider) authorizeSecurityGroupEgress(ctx context.Context, firewallRuleID string, req provider.IPPermission) error {
	_, err := p.ec2.AuthorizeSecurityGroupEgress(&ec2.AuthorizeSecurityGroupEgressInput{
		GroupId: aws.String(firewallRuleID),
		IpPermissions: []*ec2.IpPermission{
			converter.EncodeIPPermission(req),
		},
	})
	if err != nil {
		return converter.DecodeEC2Error("failed to authorize security group egress permission", err)
	}

	return nil
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
		return converter.DecodeEC2Error("failed to disassociate security group", err)
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
