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
		if err := applyPermissions(ctx, log, firewallRuleID, addFunc, toAdd); err != nil {
			return err
		}
	}

	return nil
}

// PermFunc describes a permission function authorize / revoke ingress / egress
type PermFunc func(ctx context.Context, log logr.Logger, firewallRuleID string, req IPPermission) error

// applyPermissions perform asynchronous calls on given PermFunc to
// authorize / ingress / egress permission.
func applyPermissions(
	ctx context.Context,
	log logr.Logger,
	firewallRuleID string,
	permFunc PermFunc,
	permission IPPermission,
) error {
	return permFunc(ctx, log, firewallRuleID, permission)
}

// containsPermission returns if given Permission slice contains Permission.
func ContainsPermission(slice []*IPPermission, elem *IPPermission) bool {
	for _, e := range slice {
		if reflect.DeepEqual(e, elem) {
			return true
		}
	}
	return false
}

// IsPermissionDuplicate checks if the given IPPermission element appears more than once in the provided slice.
// It returns true if the element is a duplicate, otherwise false.
//
// Parameters:
//   - slice: A slice of pointers to IPPermission elements to be checked.
//   - elem: A pointer to the IPPermission element to be checked for duplication.
//
// Returns:
//   - bool: True if the element is a duplicate, otherwise false.
func IsPermissionDuplicate(slice []*IPPermission, elem *IPPermission) bool {
	count := 0
	for _, e := range slice {
		if reflect.DeepEqual(e, elem) {
			count++
		}
	}
	return count > 1
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
