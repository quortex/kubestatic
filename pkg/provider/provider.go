// Package provider contains the cloud providers related interfaces and models.
package provider

import (
	"context"

	corev1 "k8s.io/api/core/v1"
)

// Provider describes a cloud provider
type Provider interface {
	Client
	GetInstanceID(corev1.Node) string
	// HasGroupedFirewallRules describes wether firewall rule groups are
	// supported by the provider or not (e.g. AWS SecurityGroups).
	HasGroupedFirewallRules() bool
}

// The necessary methods for a provider client are described here.
// According of the Provider.HasGroupedFirewallRules implementation,
// one of the CreateFirewallRule / CreateFirewallRuleGroup and
// UpdateFirewallRule / UpdateFirewallRuleGroup methods must be implemented.
type Client interface {
	GetInstance(ctx context.Context, instanceID string) (*Instance, error)
	GetAddress(ctx context.Context, addressID string) (*Address, error)
	CreateAddress(ctx context.Context) (*Address, error)
	DeleteAddress(ctx context.Context, addressID string) error
	AssociateAddress(ctx context.Context, req AssociateAddressRequest) error
	DisassociateAddress(ctx context.Context, req DisassociateAddressRequest) error
	FetchFirewallRule(ctx context.Context, firewallRuleGroupID string) error
	CreateFirewallRule(ctx context.Context, req CreateFirewallRuleRequest) (string, error)
	CreateFirewallRuleGroup(ctx context.Context, req CreateFirewallRuleGroupRequest) (string, error)
	UpdateFirewallRule(ctx context.Context, req UpdateFirewallRuleRequest) (*FirewallRule, error)
	UpdateFirewallRuleGroup(ctx context.Context, req UpdateFirewallRuleGroupRequest) (string, error)
	DeleteFirewallRule(ctx context.Context, firewallRuleID string) error
	AssociateFirewallRule(ctx context.Context, req AssociateFirewallRuleRequest) error
	DisassociateFirewallRule(ctx context.Context, req AssociateFirewallRuleRequest) error
}
