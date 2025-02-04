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
	addFunc, delFunc PermFunc,
	rule *IPPermission,
	get []*IPPermission,
) error {
	// Compute which permissions to add and delete
	//toDel, toAdd := computePermissionRequests(want, get)

	// First we delete extra permissions to avoid conflicts.
	//if len(toDel) != 0 {
	//	if err := applyPermissions(ctx, log, firewallRuleID, delFunc, toDel); err != nil {
	//		return err
	//	}
	//}

	if !containsPermission(get, rule) {
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

// computePermissionRequests takes in parameters the desired permissions
// and the current permissions and returns the permissions to add and the
// permissions to destroy to reach the desired state
func computePermissionRequests(want, get []*IPPermission) (toDel, toAdd []IPPermission) {
	// Compute which permissions to add.
	for i := len(want) - 1; i >= 0; i-- {
		p := want[i]
		if !containsPermission(get, p) {
			toAdd = append(toAdd, IPPermission{
				IPRanges: p.IPRanges,
				FromPort: p.FromPort,
				Protocol: p.Protocol,
				ToPort:   p.ToPort,
			})

			want = append(want[:i], want[i+1:]...)
		}
	}

	// Compute which permissions to revoke.
	for _, e := range get {
		if !containsPermission(want, e) {
			toDel = append(toDel, IPPermission{
				IPRanges: e.IPRanges,
				FromPort: e.FromPort,
				Protocol: e.Protocol,
				ToPort:   e.ToPort,
			})
		}
	}

	return
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
func containsPermission(slice []*IPPermission, elem *IPPermission) bool {
	for _, e := range slice {
		if reflect.DeepEqual(e, elem) {
			return true
		}
	}
	return false
}

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
