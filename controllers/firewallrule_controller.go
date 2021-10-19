/*
Copyright 2021.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/go-logr/logr"
	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/quortex/kubestatic/api/v1alpha1"
	"github.com/quortex/kubestatic/pkg/helper"
	"github.com/quortex/kubestatic/pkg/provider"
)

const (
	// firewallRuleFinalizer is a finalizer for FirewallRule
	firewallRuleFinalizer = "firewallrule.finalizers.kubestatic.quortex.io"
)

// FirewallRuleReconciler reconciles a FirewallRule object
type FirewallRuleReconciler struct {
	client.Client
	Log      logr.Logger
	Scheme   *runtime.Scheme
	Provider provider.Provider
}

//+kubebuilder:rbac:groups=kubestatic.quortex.io,resources=firewallrules,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=kubestatic.quortex.io,resources=firewallrules/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=kubestatic.quortex.io,resources=firewallrules/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *FirewallRuleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("firewallrule", req.NamespacedName, "reconciliationID", uuid.New().String())

	log.V(1).Info("FirewallRule reconciliation started")
	defer log.V(1).Info("FirewallRule reconciliation done")

	firewallRule := &v1alpha1.FirewallRule{}
	if err := r.Get(ctx, req.NamespacedName, firewallRule); err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Return and don't requeue
			log.Info("FirewallRule resource not found. Ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		// Error reading the object - requeue the request.
		log.Error(err, "Failed to get FirewallRule")
		return ctrl.Result{}, err
	}

	// Lifecycle reconciliation
	if firewallRule.ObjectMeta.DeletionTimestamp.IsZero() {
		return r.reconcileFirewallRule(ctx, log, firewallRule)
	}

	// Deletion reconciliation
	return r.reconcileFirewallRuleDeletion(ctx, log, firewallRule)
}

func (r *FirewallRuleReconciler) reconcileFirewallRule(ctx context.Context, log logr.Logger, rule *v1alpha1.FirewallRule) (ctrl.Result, error) {
	// 1st STEP
	//
	// Add finalizer
	if !helper.ContainsString(rule.ObjectMeta.Finalizers, firewallRuleFinalizer) {
		rule.ObjectMeta.Finalizers = append(rule.ObjectMeta.Finalizers, firewallRuleFinalizer)
		log.V(1).Info("Updating FirewallRule", "finalizer", firewallRuleFinalizer)
		return ctrl.Result{}, r.Update(ctx, rule)
	}

	// 2nd STEP
	//
	// Reserve firewall
	if rule.Status.State == v1alpha1.FirewallRuleStateNone {
		// Create firewall rule
		res, err := r.Provider.CreateFirewallRule(ctx, provider.CreateFirewallRuleRequest{
			FirewallRuleSpec: encodeFirewallRuleSpec(rule),
		})
		if err != nil {
			log.Error(err, "Failed to create firewall rule")
			return ctrl.Result{}, err
		}
		log.Info("Created firewall rule", "id", res.FirewallRuleID)

		// Update status
		rule.Status.State = v1alpha1.FirewallRuleStateReserved
		rule.Status.FirewallRuleID = &res.FirewallRuleID
		lastApplied, err := json.Marshal(rule.Spec)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("Failed to marshal last applied firewallrule: %w", err)
		}
		rule.Status.LastApplied = helper.StringPointerOrNil(string(lastApplied))
		log.V(1).Info("Updating FirewallRule", "state", rule.Status.State, "firewallRuleID", rule.Status.FirewallRuleID)
		return ctrl.Result{}, r.Status().Update(ctx, rule)
	} else {
		lastApplied := &v1alpha1.FirewallRuleSpec{}
		if err := json.Unmarshal([]byte(helper.StringValue(rule.Status.LastApplied)), lastApplied); err != nil {
			return ctrl.Result{}, fmt.Errorf("Failed to unmarshal last applied firewallrule: %w", err)
		}

		// Firewall rule has changed, perform update
		if !reflect.DeepEqual(rule.Spec, *lastApplied) {
			// Update firewall rule
			firewallRuleID := helper.StringValue(rule.Status.FirewallRuleID)
			res, err := r.Provider.UpdateFirewallRule(ctx, provider.UpdateFirewallRuleRequest{
				FirewallRuleID:   firewallRuleID,
				FirewallRuleSpec: encodeFirewallRuleSpec(rule),
			})
			if err != nil {
				log.Error(err, "Failed to update firewall rule", "id", firewallRuleID)
				return ctrl.Result{}, err
			}
			log.Info("Updated firewall rule", "id", res.FirewallRuleID)

			// Update status
			lastApplied, err := json.Marshal(rule.Spec)
			if err != nil {
				return ctrl.Result{}, fmt.Errorf("Failed to marshal last applied firewallrule: %w", err)
			}
			rule.Status.LastApplied = helper.StringPointerOrNil(string(lastApplied))
			log.V(1).Info("Updating FirewallRule", "state", rule.Status.State, "firewallRuleID", rule.Status.FirewallRuleID)
			return ctrl.Result{}, r.Status().Update(ctx, rule)
		}
	}

	// 3rd STEP
	//
	// Finally associate firewall rule to instance network interface.
	if rule.IsReserved() {
		if rule.Spec.NodeName != nil {
			// Get node from FirewallRule spec
			var node corev1.Node
			if err := r.Get(ctx, types.NamespacedName{Name: *rule.Spec.NodeName}, &node); err != nil {
				if errors.IsNotFound(err) {
					// Invalid nodeName, remove FirewallRule nodeName attribute.
					log.Info("Node not found. Removing it from FirewallRule spec", "nodeName", rule.Spec.NodeName)
					rule.Spec.NodeName = nil
					return ctrl.Result{}, r.Update(ctx, rule)
				}
				// Error reading the object - requeue the request.
				log.Error(err, "Failed to get Node")
				return ctrl.Result{}, err
			}

			// Retrieve node instance
			instanceID := r.Provider.GetInstanceID(node)
			res, err := r.Provider.GetInstance(ctx, instanceID)
			if err != nil {
				log.Error(err, "Failed to get instance", "id", instanceID)
				return ctrl.Result{}, err
			}

			// Get the first network interface with a public IP address
			var networkInterface *provider.NetworkInterface
			for _, elem := range res.NetworkInterfaces {
				if elem != nil && elem.PublicIP != nil {
					networkInterface = elem
					break
				}
			}
			if networkInterface == nil {
				err := fmt.Errorf("no network interface with public IP found for instance %s", instanceID)
				log.Error(err, "Cannot associate a firewall rule with this instance", "instanceID", instanceID)
				return ctrl.Result{}, err
			}

			// Finally, associate firewall rule to instance network interface, then update status.
			if err := r.Provider.AssociateFirewallRule(ctx, provider.AssociateFirewallRuleRequest{
				FirewallRuleID:     *rule.Status.FirewallRuleID,
				NetworkInterfaceID: networkInterface.NetworkInterfaceID,
			}); err != nil {
				log.Error(err, "Failed to associate firewall rule", "firewallRuleID", *rule.Status.FirewallRuleID, "instanceID", instanceID, "networkInterfaceID", networkInterface.NetworkInterfaceID)
				return ctrl.Result{}, err
			}
			log.Info("Associated firewall rule", "firewallRuleID", *rule.Status.FirewallRuleID, "instanceID", instanceID, "networkInterfaceID", networkInterface.NetworkInterfaceID)

			// Update status
			rule.Status.State = v1alpha1.FirewallRuleStateAssociated
			rule.Status.InstanceID = &instanceID
			rule.Status.NetworkInterfaceID = &networkInterface.NetworkInterfaceID
			log.V(1).Info("Updating FirewallRule", "state", rule.Status.State, "instanceID", rule.Status.InstanceID, "networkInterfaceID", rule.Status.NetworkInterfaceID)
			return ctrl.Result{}, r.Status().Update(ctx, rule)
		}

		// No spec.nodeName, no association, end reconciliation for FirewallRule.
		log.V(1).Info("No No spec.nodeName, no association, end reconciliation for FirewallRule.")
		return ctrl.Result{}, nil
	}

	// FirewallRule reliability check
	//
	// Check if the associated node still exists and disassociate it if it does not.
	// No nodeName or no living node, set state back to "Reserved"
	if rule.IsAssociated() {
		if rule.Spec.NodeName != nil {
			// Get node from FirewallRule spec
			var node corev1.Node
			if err := r.Get(ctx, types.NamespacedName{Name: *rule.Spec.NodeName}, &node); err != nil {
				if errors.IsNotFound(err) {
					// Invalid nodeName, remove FirewallRule nodeName attribute.
					log.Info("Node not found. Removing it from FirewallRule spec", "nodeName", rule.Spec.NodeName)

					// Set status back to Reserved
					rule.Status.State = v1alpha1.FirewallRuleStateReserved
					log.V(1).Info("Updating FirewallRule", "state", rule.Status.State, "InstanceID", rule.Status.InstanceID)
					if err != r.Status().Update(ctx, rule) {
						log.Error(err, "Failed to update FirewallRule status", "firewallRule", rule.Name, "status", rule.Status.State)
						return ctrl.Result{}, err
					}

					rule.Spec.NodeName = nil
					return ctrl.Result{}, r.Update(ctx, rule)
				}
				// Error reading the object - requeue the request.
				log.Error(err, "Failed to get Node")
				return ctrl.Result{}, err
			}

			// Node not being deleted, reconciliation done
			if node.ObjectMeta.DeletionTimestamp.IsZero() {
				return ctrl.Result{}, nil
			}
		}

		// Set state back to "Reserved", disassociate firewall rule and end reconciliation
		return r.disassociateFirewallRule(ctx, r.Provider, log, rule)
	}

	return ctrl.Result{}, nil
}

func (r *FirewallRuleReconciler) reconcileFirewallRuleDeletion(ctx context.Context, log logr.Logger, rule *v1alpha1.FirewallRule) (ctrl.Result, error) {
	// 1st STEP
	//
	// Reconciliation of a possible firewall rule associated with the instance.
	// If a rule is associated with the instance, disassociate it.
	if rule.IsAssociated() {
		return r.disassociateFirewallRule(ctx, r.Provider, log, rule)
	}

	// 2nd STEP
	//
	// Release unassociated firewall rule.
	if rule.IsReserved() {
		if err := r.Provider.DeleteFirewallRule(ctx, *rule.Status.FirewallRuleID); err != nil {
			if !provider.IsErrNotFound(err) {
				log.Error(err, "Failed to delete FirewallRule", "firewallRuleID", *rule.Status.FirewallRuleID)
				return ctrl.Result{}, err
			}
			log.V(1).Info("FirewallRule not found", "firewallRuleID", *rule.Status.FirewallRuleID)
		}
		log.Info("Deleted FirewallRule", "firewallRuleID", *rule.Status.FirewallRuleID)

		// Update status
		rule.Status.State = v1alpha1.FirewallRuleStateNone
		rule.Status.FirewallRuleID = nil
		log.V(1).Info("Updating FirewallRule", "state", rule.Status.State)
		return ctrl.Result{}, r.Status().Update(ctx, rule)
	}

	// 3rd STEP
	//
	// Remove finalizer to release FirewallRule
	if rule.Status.State == v1alpha1.FirewallRuleStateNone {
		if helper.ContainsString(rule.Finalizers, firewallRuleFinalizer) {
			rule.Finalizers = helper.RemoveString(rule.Finalizers, firewallRuleFinalizer)
			return ctrl.Result{}, r.Update(ctx, rule)
		}
	}

	return ctrl.Result{}, nil
}

// disassociateFirewallRule performs firewall rule disassociation tasks
func (r *FirewallRuleReconciler) disassociateFirewallRule(ctx context.Context, pvd provider.Provider, log logr.Logger, rule *v1alpha1.FirewallRule) (ctrl.Result, error) {
	// Get firewall rule and disassociate it
	if rule.Status.FirewallRuleID != nil {
		err := pvd.DisassociateFirewallRule(ctx, provider.AssociateFirewallRuleRequest{
			FirewallRuleID:     *rule.Status.FirewallRuleID,
			NetworkInterfaceID: *rule.Status.NetworkInterfaceID,
		})
		if err != nil {
			if !provider.IsErrNotFound(err) {
				log.Error(err, "Failed to disassociate firewall rule", "firewallRuleID", *rule.Status.FirewallRuleID, "networkInterfaceID", *rule.Status.NetworkInterfaceID)
				return ctrl.Result{}, err
			}
			log.Info("Firewall rule already disassociated", "firewallRuleID", *rule.Status.FirewallRuleID)
		} else {
			log.Info("Disassociated firewall rule", "firewallRuleID", *rule.Status.FirewallRuleID, "networkInterfaceID", *rule.Status.NetworkInterfaceID)
		}
	}

	// Update status
	rule.Status.State = v1alpha1.FirewallRuleStateReserved
	rule.Status.InstanceID = nil
	rule.Status.NetworkInterfaceID = nil
	log.V(1).Info("Updating FirewallRule", "state", rule.Status.State)
	if err := r.Status().Update(ctx, rule); err != nil {
		log.Error(err, "Failed to update FirewallRule state", "firewallRule", rule.Name)
		return ctrl.Result{}, err
	}

	log.V(1).Info("Removing FirewallRule NodeName", "firewallRule", rule.Name)
	rule.Spec.NodeName = nil
	return ctrl.Result{}, r.Update(ctx, rule)
}

// SetupWithManager sets up the controller with the Manager.
func (r *FirewallRuleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.FirewallRule{}).
		Complete(r)
}

// encodeFirewallRuleSpec converts an api FirewallRule to a FirewallRuleSpec.
func encodeFirewallRuleSpec(data *v1alpha1.FirewallRule) provider.FirewallRuleSpec {
	return provider.FirewallRuleSpec{
		Name:        data.Name,
		Description: data.Spec.Description,
		Direction:   encodeDirection(data.Spec.Direction),
		IPPermission: &provider.IPPermission{
			FromPort: data.Spec.FromPort,
			Protocol: data.Spec.Protocol,
			IPRanges: encodeIPRanges(data.Spec.IPRanges),
			ToPort:   data.Spec.ToPort,
		},
	}
}

// encodeIPRange converts an api IPRange to an IPRange.
func encodeIPRange(data *v1alpha1.IPRange) *provider.IPRange {
	if data == nil {
		return nil
	}

	return &provider.IPRange{
		CIDR:        data.CIDR,
		Description: data.Description,
	}
}

// encodeIPRange converts an api IPRange slice to an IPRange slice.
func encodeIPRanges(data []*v1alpha1.IPRange) []*provider.IPRange {
	if data == nil {
		return make([]*provider.IPRange, 0)
	}

	res := make([]*provider.IPRange, len(data))
	for i, e := range data {
		res[i] = encodeIPRange(e)
	}
	return res
}

// encodeDirection converts an api Direction to a Direction.
func encodeDirection(data v1alpha1.Direction) provider.Direction {
	switch data {
	case v1alpha1.DirectionEgress:
		return provider.DirectionEgress
	case v1alpha1.DirectionIngress:
		return provider.DirectionIngress
	}
	return provider.Direction("")
}
