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
}

// Client describe the cloud provider client.
type Client interface {
	GetInstance(ctx context.Context, instanceID string) (*Instance, error)
	GetAddress(ctx context.Context, addressID string) (*Address, error)
	CreateAddress(ctx context.Context) (*Address, error)
	DeleteAddress(ctx context.Context, addressID string) error
	AssociateAddress(ctx context.Context, req AssociateAddressRequest) error
	DisassociateAddress(ctx context.Context, req DisassociateAddressRequest) error
	GetFirewallRule(ctx context.Context, firewallRuleID string) (*FirewallRule, error)
	CreateFirewallRule(ctx context.Context, req CreateFirewallRuleRequest) (*FirewallRule, error)
	UpdateFirewallRule(ctx context.Context, req UpdateFirewallRuleRequest) (*FirewallRule, error)
	DeleteFirewallRule(ctx context.Context, firewallRuleID string) error
	AssociateFirewallRule(ctx context.Context, req AssociateFirewallRuleRequest) error
	DisassociateFirewallRule(ctx context.Context, req AssociateFirewallRuleRequest) error
}
