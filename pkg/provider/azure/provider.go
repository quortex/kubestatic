// Package aws contains the provider implementation for AWS.
package azure

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"path"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/Azure/azure-sdk-for-go/services/compute/mgmt/2021-07-01/compute"
	"github.com/Azure/azure-sdk-for-go/services/network/mgmt/2019-11-01/network"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/quortex/kubestatic/pkg/provider"
	"github.com/quortex/kubestatic/pkg/provider/azure/converter"
)

var resourceGroup string
var locationDefault string

type azureProvider struct {
	ipClient   *network.PublicIPAddressesClient
	inetClient *network.InterfacesClient
	vmClient   *compute.VirtualMachineScaleSetVMsClient
}

// NewProvider instantiate a Provider implementation for Azure
func NewProvider() (provider.Provider, error) {
	// By default NewSession loads credentials from the shared credentials file (~/.aws/credentials)
	//
	// The Session will attempt to load configuration and credentials from the environment,
	// configuration files, and other credential sources. The order configuration is loaded in is:
	// * Environment Variables
	// * Shared Credentials file
	// * Shared Configuration file (if SharedConfig is enabled)
	// * EC2 Instance Metadata (credentials only)

	resourceGroup = os.Getenv("AZURE_RESOURCE_GROUP")
	locationDefault = os.Getenv("AZURE_LOCATION_DEFAULT")

	ipClient := network.NewPublicIPAddressesClient(os.Getenv("AZURE_SUBSCRIPTION_ID"))
	ipClient.Authorizer, _ = auth.NewAuthorizerFromEnvironment()
	inetClient := network.NewInterfacesClient(os.Getenv("AZURE_SUBSCRIPTION_ID"))
	inetClient.Authorizer, _ = auth.NewAuthorizerFromEnvironment()
	vmClient := compute.NewVirtualMachineScaleSetVMsClient(os.Getenv("AZURE_SUBSCRIPTION_ID"))
	vmClient.Authorizer, _ = auth.NewAuthorizerFromEnvironment()

	return &azureProvider{
		ipClient:   &ipClient,
		inetClient: &inetClient,
		vmClient:   &vmClient,
	}, nil
}

func retrieveInstanceNetworkInterfaceMacAddress() (string, error) {
	panic("unimplemented method")
}

func retrieveVPCID() (string, error) {
	panic("unimplemented method")
}

func (p *azureProvider) GetInstanceID(node corev1.Node) string {
	return path.Base(node.Spec.ProviderID)
}

func (p *azureProvider) GetInstance(ctx context.Context, instanceID string) (*provider.Instance, error) {
	panic("unimplemented method")
}

func (p *azureProvider) GetAddress(ctx context.Context, addressID string) (*provider.Address, error) {
	res, err := p.ipClient.Get(ctx, resourceGroup, addressID, "")

	if err != nil {
		//TODO: Convert error to QX error
		return nil, err
	}

	return converter.DecodeAddress(&res), nil
}

func randSeq(n int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func (p *azureProvider) CreateAddress(ctx context.Context) (*provider.Address, error) {
	rand.Seed(time.Now().UnixNano())
	var ipName = "kubestatic-" + randSeq(10)

	future, err := p.ipClient.CreateOrUpdate(
		ctx,
		resourceGroup,
		ipName,
		network.PublicIPAddress{
			Name:     to.StringPtr(ipName),
			Location: to.StringPtr(locationDefault),
			PublicIPAddressPropertiesFormat: &network.PublicIPAddressPropertiesFormat{
				PublicIPAddressVersion:   network.IPv4,
				PublicIPAllocationMethod: network.Static,
			},
		},
	)
	if err != nil {
		//TODO: Convert error to QX error
		return nil, fmt.Errorf("cannot create public ip address: %v", err)
	}

	err = future.WaitForCompletionRef(ctx, p.ipClient.Client)

	if err != nil {
		return nil, fmt.Errorf("cannot get public ip address create or update future response: %v", err)
	}

	return p.GetAddress(ctx, ipName)
}

func (p *azureProvider) DeleteAddress(ctx context.Context, addressID string) error {
	_, err := p.ipClient.Delete(ctx, resourceGroup, addressID)

	if err != nil {
		return err
	}

	return nil
}

func (p *azureProvider) AssociateAddress(ctx context.Context, req provider.AssociateAddressRequest) error {
	panic("unimplemented method")
}

func (p *azureProvider) DisassociateAddress(ctx context.Context, req provider.DisassociateAddressRequest) error {
	panic("unimplemented method")
}

func (p *azureProvider) getSecurityGroup(ctx context.Context, firewallRuleID string) (*ec2.SecurityGroup, error) {
	panic("unimplemented method")
}

func (p *azureProvider) GetFirewallRule(ctx context.Context, firewallRuleID string) (*provider.FirewallRule, error) {
	panic("unimplemented method")
}

func (p *azureProvider) CreateFirewallRule(ctx context.Context, req provider.CreateFirewallRuleRequest) (string, error) {
	panic("unimplemented method for AWS: CreateFirewallRule, use CreateFirewallRuleGroup instead")
}

func (p *azureProvider) UpdateFirewallRuleGroup(ctx context.Context, req provider.UpdateFirewallRuleGroupRequest) (string, error) {
	panic("unimplemented method for AWS: CreateFirewallRule, use CreateFirewallRuleGroup instead")
}

func (p *azureProvider) DeleteFirewallRule(ctx context.Context, firewallRuleID string) error {
	panic("unimplemented method")
}

func (p *azureProvider) authorizeSecurityGroupIngress(ctx context.Context, firewallRuleID string, req provider.IPPermission) error {
	panic("unimplemented method")
}

func (p *azureProvider) revokeSecurityGroupIngress(ctx context.Context, firewallRuleID string, req provider.IPPermission) error {
	panic("unimplemented method")
}

func (p *azureProvider) authorizeSecurityGroupEgress(ctx context.Context, firewallRuleID string, req provider.IPPermission) error {
	panic("unimplemented method")
}

func (p *azureProvider) revokeSecurityGroupEgress(ctx context.Context, firewallRuleID string, req provider.IPPermission) error {
	panic("unimplemented method")
}

func (p *azureProvider) AssociateFirewallRule(ctx context.Context, req provider.AssociateFirewallRuleRequest) error {
	panic("unimplemented method")
}
func (p *azureProvider) UpdateFirewallRule(ctx context.Context, req provider.UpdateFirewallRuleRequest) (*provider.FirewallRule, error) {
	panic("unimplemented method for AWS: UpdateFirewallRule, use UpdateFirewallRuleGroup instead")
}
func (p *azureProvider) DisassociateFirewallRule(ctx context.Context, req provider.AssociateFirewallRuleRequest) error {
	panic("unimplemented method")
}
func (p *azureProvider) CreateFirewallRuleGroup(ctx context.Context, req provider.CreateFirewallRuleGroupRequest) (string, error) {
	panic("unimplemented method for AWS: CreateFirewallRule, use CreateFirewallRuleGroup instead")
}

func (p *azureProvider) FetchFirewallRule(ctx context.Context, firewallRuleGroupID string) error {
	panic("unimplemented method")
}
func (p *azureProvider) HasGroupedFirewallRules() bool {
	return true
}
