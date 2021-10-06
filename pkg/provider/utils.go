// Package provider contains the cloud providers related interfaces and models.
package provider

import (
	"context"
	"reflect"
	"sync"
)

// ReconcilePermissions perform create / delete on given permissions
// to to reach the desired state of firewall rules.
func ReconcilePermissions(
	ctx context.Context,
	firewallRuleID string,
	addFunc, delFunc PermFunc,
	want, get []*IPPermission,
) error {
	// Compute which permissions to add and delete
	toDel, toAdd := computePermissionRequests(want, get)

	// First we delete extra permissions to avoid conflicts.
	if len(toDel) != 0 {
		if err := applyPermissions(ctx, firewallRuleID, delFunc, toDel); err != nil {
			return err
		}
	}

	// Then, create new permissions.
	if len(toAdd) != 0 {
		if err := applyPermissions(ctx, firewallRuleID, addFunc, toAdd); err != nil {
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
type PermFunc func(ctx context.Context, firewallRuleID string, req IPPermission) error

// applyPermissions perform asynchronous calls on given PermFunc to
// authorize / revoke ingress / egress permissions by batch.
func applyPermissions(
	ctx context.Context,
	firewallRuleID string,
	permFunc PermFunc,
	permissions []IPPermission,
) error {
	var wg sync.WaitGroup
	cDone := make(chan bool)
	cErr := make(chan error)

	for _, e := range permissions {
		wg.Add(1)
		go func(ctx context.Context, id string, req IPPermission) {
			defer wg.Done()
			if err := permFunc(ctx, id, req); err != nil {
				cErr <- err
			}
		}(ctx, firewallRuleID, e)
	}

	// Final goroutine to wait until WaitGroup is done
	go func() {
		wg.Wait()
		close(cDone)
	}()

	// Wait until either WaitGroup is done or an error is received through the channel
	select {
	case <-cDone:
		break
	case err := <-cErr:
		close(cErr)
		return err
	}

	return nil
}

// containsPermission returns if given Permisssion slice contains Permission.
func containsPermission(slice []*IPPermission, elem *IPPermission) bool {
	for _, e := range slice {
		if reflect.DeepEqual(e, elem) {
			return true
		}
	}
	return false
}
