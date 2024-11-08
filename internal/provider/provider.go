// Package provider contains the cloud providers related interfaces and models.
package provider

import (
	"context"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"

	"github.com/quortex/kubestatic/api/v1alpha1"
)

// Provider describes a cloud provider
type Provider interface {
	Client
	GetInstanceID(corev1.Node) string
}

// The necessary methods for a provider client are described here.
type Client interface {
	ReconcileFirewallRules(ctx context.Context,
		log logr.Logger,
		nodeName,
		instanceID string,
		firewallRules []v1alpha1.FirewallRule,
	) (v1alpha1.FirewallRuleStatus, error)
	ReconcileFirewallRulesDeletion(ctx context.Context, log logr.Logger, nodeName string) error
	ReconcileExternalIP(ctx context.Context, log logr.Logger, instanceID string, externalIP *v1alpha1.ExternalIP) (v1alpha1.ExternalIPStatus, error)
	ReconcileExternalIPDeletion(ctx context.Context, log logr.Logger, externalIP *v1alpha1.ExternalIP) error
}
