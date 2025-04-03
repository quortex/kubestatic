// Package provider contains the cloud providers related interfaces and models.
package provider

import (
	"context"
	"reflect"

	"github.com/go-logr/logr"
)

// ReconcilePermissions perform create / delete on given permissions
// to reach the desired state of firewall rules.
func ReconcilePermissions(
	ctx context.Context,
	log logr.Logger,
	firewallRuleID string,
	addFunc PermFunc,
	rule *IPPermission,
	get []*IPPermission,
) error {
	if !ContainsPermission(get, rule) {
		toAdd := IPPermission{
			IPRanges: rule.IPRanges,
			FromPort: rule.FromPort,
			Protocol: rule.Protocol,
			ToPort:   rule.ToPort,
		}
		if err := addFunc(ctx, log, firewallRuleID, toAdd); err != nil {
			return err
		}
	}

	return nil
}

// PermFunc describes a permission function authorize / revoke ingress / egress
type PermFunc func(ctx context.Context, log logr.Logger, firewallRuleID string, req IPPermission) error

// containsPermission returns if given Permission slice contains Permission.
func ContainsPermission(slice []*IPPermission, elem *IPPermission) bool {
	for _, e := range slice {
		if reflect.DeepEqual(e, elem) {
			return true
		}
	}
	return false
}

// GetIngressIPPermissions get ingress permissions from rule slice.
func GetIngressIPPermissions(slice []FirewallRuleSpec) []*IPPermission {
	res := []*IPPermission{}
	for _, e := range slice {
		if e.Direction == DirectionIngress {
			res = append(res, e.IPPermission)
		}
	}
	return res
}

// GetEgressIPPermission get egress permissions from rule slice.
func GetEgressIPPermissions(slice []FirewallRuleSpec) []*IPPermission {
	res := []*IPPermission{}
	for _, e := range slice {
		if e.Direction == DirectionEgress {
			res = append(res, e.IPPermission)
		}
	}
	return res
}
