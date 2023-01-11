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
	"k8s.io/utils/pointer"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/quortex/kubestatic/api/v1alpha1"
	"github.com/quortex/kubestatic/pkg/helper"
	"github.com/quortex/kubestatic/pkg/provider"
)

const (
	// firewallRuleFinalizer is a finalizer for FirewallRule
	firewallRuleFinalizer   = "firewallrule.finalizers.kubestatic.quortex.io"
	firewallRuleNodeNameKey = ".spec.nodeName"
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

	if firewallRule.Spec.DisableReconciliation {
		log.Info("Reconciliation disabled")
		return ctrl.Result{}, nil
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

	if helper.StringValue(rule.Spec.NodeName) == "" {
		log.Info("Empty nodeName, nothing to do !")
		return ctrl.Result{}, nil
	}

	// 2nd STEP
	//
	// Reserve firewall
	if rule.Status.State == v1alpha1.FirewallRuleStateNone {
		// Create firewall rule
		// In the case of standalone firewall rules, we create it,
		// otherwise, we update the group dedicated to the node.
		var id string
		var err error
		if r.Provider.HasGroupedFirewallRules() {
			// List FirewallRules with identical nodeName
			frs := &v1alpha1.FirewallRuleList{}
			if err := r.List(ctx, frs, client.MatchingFields{firewallRuleNodeNameKey: *rule.Spec.NodeName}); err != nil {
				log.Error(err, "Unable to list FirewallRules")
				return ctrl.Result{}, err
			}

			// Check for other rules associated to the node.
			// If there is already one, we update the group of rules, if not, we create a new group.
			rulesAssociated := v1alpha1.FilterFirewallRules(frs.Items, func(fr v1alpha1.FirewallRule) bool {
				return fr.Name != rule.Name && fr.Status.State != v1alpha1.FirewallRuleStateNone
			})
			if len(rulesAssociated) > 0 {
				firewallRuleID := helper.StringValue(rulesAssociated[0].Status.FirewallRuleID)
				log.V(1).Info("Updating FirewallRule group", "firewallRuleID", firewallRuleID)
				id, err = r.Provider.UpdateFirewallRuleGroup(ctx, encodeUpdateFirewallRuleGroupRequest(firewallRuleID, frs.Items))
				if err != nil {
					log.Error(err, "Unable to update FirewallRules")
					return ctrl.Result{}, err
				}
			} else {
				// No existing group, we create a new one.
				log.V(1).Info("Creating FirewallRule group")
				id, err = r.Provider.CreateFirewallRuleGroup(
					ctx,
					encodeCreateFirewallRuleGroupRequest(
						fmt.Sprintf("kubestatic-%s", randomString(10)),
						fmt.Sprintf("Kubestatic managed group for node %s", *rule.Spec.NodeName),
						frs.Items,
					),
				)
			}
		} else {
			// Standalone rules, we simply create a rule.
			log.V(1).Info("Creating FirewallRule")
			id, err = r.Provider.CreateFirewallRule(ctx, encodeCreateFirewallRuleRequest(rule))
		}

		if err != nil {
			log.Error(err, "Failed to create firewall rule")
			return ctrl.Result{}, err
		}
		log.Info("Created firewall rule", "id", id)

		// Update status
		rule.Status.State = v1alpha1.FirewallRuleStateReserved
		rule.Status.FirewallRuleID = &id
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

		// Update firewall rule.
		// In the case of standalone firewall rules, we update it,
		// otherwise, we update the group dedicated to the node.
		if !reflect.DeepEqual(rule.Spec, *lastApplied) {
			// Update firewall rule
			firewallRuleID := helper.StringValue(rule.Status.FirewallRuleID)
			var err error
			if r.Provider.HasGroupedFirewallRules() {
				// List FirewallRules with identical nodeName
				frs := &v1alpha1.FirewallRuleList{}
				if err := r.List(ctx, frs, client.MatchingFields{firewallRuleNodeNameKey: *rule.Spec.NodeName}); err != nil {
					log.Error(err, "Unable to list FirewallRules")
					return ctrl.Result{}, err
				}
				log.V(1).Info("Updating FirewallRule group", "firewallRuleID", firewallRuleID)
				_, err = r.Provider.UpdateFirewallRuleGroup(ctx, encodeUpdateFirewallRuleGroupRequest(firewallRuleID, frs.Items))
			} else {
				log.V(1).Info("Updating FirewallRule", "firewallRuleID", firewallRuleID)
				_, err = r.Provider.UpdateFirewallRule(ctx, encodeUpdateFirewallRuleRequest(firewallRuleID, rule))
			}

			if err != nil {
				log.Error(err, "Failed to update firewall rule", "id", firewallRuleID)
				return ctrl.Result{}, err
			}
			log.Info("Updated firewall rule", "id", firewallRuleID)

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
			// This is needed because we could have multiple network interfaces,
			// for example on EKS we have the public one, as well as one or more created by the EKS CNI.
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
		log.V(1).Info("No spec.nodeName, no association, end reconciliation for FirewallRule.")
		return ctrl.Result{}, nil
	}

	// FirewallRule reliability check
	//
	// Check if the associated node still exists and disassociate it if it does not.
	// No nodeName or no living node, set state back to "Reserved"
	if rule.Status.State != v1alpha1.FirewallRuleStateNone {
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

			// If the node is not being deleted and has an instance corresponding to its node name, the reconciliation is done
			// This check exist to disassociate the rule of the old instance if the node name change
			if node.ObjectMeta.DeletionTimestamp.IsZero() && pointer.StringPtrDerefOr(rule.Status.InstanceID, "") == r.Provider.GetInstanceID(node) {
				return ctrl.Result{}, nil
			}
		}

		// If the rule has no node name, has an node name not matching its instance ID, or its node is being deleted
		// clear firewall rule from provider and set state back to "None"
		return r.clearFirewallRule(ctx, log, rule)
	}

	return ctrl.Result{}, nil
}

func (r *FirewallRuleReconciler) reconcileFirewallRuleDeletion(ctx context.Context, log logr.Logger, rule *v1alpha1.FirewallRule) (ctrl.Result, error) {
	// 1st STEP
	//
	// Reconciliation of a possible firewall rule associated with the instance.
	// If a rule is associated with an instance or reserved, clear it.
	if rule.Status.State != v1alpha1.FirewallRuleStateNone {
		return r.clearFirewallRule(ctx, log, rule)
	}

	// 2nd STEP
	//
	// Remove finalizer to release FirewallRule
	if helper.ContainsString(rule.Finalizers, firewallRuleFinalizer) {
		rule.Finalizers = helper.RemoveString(rule.Finalizers, firewallRuleFinalizer)
		return ctrl.Result{}, r.Update(ctx, rule)
	}

	return ctrl.Result{}, nil
}

// clearFirewallRule remove the rule from the provider rule
// In the case of grouped rules, the provider rule is updated and deleted if needed
// In the case of standalone rules the provider rule is deleted
func (r *FirewallRuleReconciler) clearFirewallRule(ctx context.Context, log logr.Logger, rule *v1alpha1.FirewallRule) (ctrl.Result, error) {
	log = log.WithValues("ruleName", rule.Name)

	if rule.Status.FirewallRuleID != nil {
		firewallRuleID := helper.StringValue(rule.Status.FirewallRuleID)

		toDelete := false
		if r.Provider.HasGroupedFirewallRules() {
			// List FirewallRules with identical nodeName
			frs := &v1alpha1.FirewallRuleList{}
			if err := r.List(ctx, frs); err != nil {
				log.Error(err, "Unable to list FirewallRules")
				return ctrl.Result{}, err
			}

			// Check for other rules associated to the node.
			// If there is other ones, we only update the group of rules, if not, we also disassociate the group.
			rules := v1alpha1.FilterFirewallRules(frs.Items, func(fr v1alpha1.FirewallRule) bool {
				return fr.Name != rule.Name && helper.StringValue(fr.Status.FirewallRuleID) == helper.StringValue(rule.Status.FirewallRuleID)
			})
			if len(rules) > 0 {
				log.V(1).Info("Updating FirewallRule", "firewallRuleID", firewallRuleID)
				if _, err := r.Provider.UpdateFirewallRuleGroup(ctx, encodeUpdateFirewallRuleGroupRequest(firewallRuleID, rules)); err != nil {
					log.Error(err, "Unable to update FirewallRules")
					return ctrl.Result{}, err
				}
			} else {
				toDelete = true
			}
		} else {
			toDelete = true
		}

		// Perform firewallrule deletion if needed
		if toDelete {
			if rule.Status.NetworkInterfaceID != nil {
				log.V(1).Info("Disassociating firewall rule on provider", "firewallRuleID", firewallRuleID)
				err := r.Provider.DisassociateFirewallRule(ctx, provider.AssociateFirewallRuleRequest{
					FirewallRuleID:     *rule.Status.FirewallRuleID,
					NetworkInterfaceID: *rule.Status.NetworkInterfaceID,
				})
				if err != nil {
					if !provider.IsErrNotFound(err) {
						log.Error(err, "Failed to disassociate firewall rule", "firewallRuleID", *rule.Status.FirewallRuleID, "networkInterfaceID", *rule.Status.NetworkInterfaceID)
						return ctrl.Result{}, err
					}
					log.V(1).Info("Firewall rule already disassociated", "firewallRuleID", *rule.Status.FirewallRuleID)
				} else {
					log.Info("Disassociated firewall rule", "firewallRuleID", *rule.Status.FirewallRuleID, "networkInterfaceID", *rule.Status.NetworkInterfaceID)
				}
			}

			log.V(1).Info("Deleting firewall rule on provider", "firewallRuleID", firewallRuleID)
			err := r.Provider.DeleteFirewallRule(ctx, *rule.Status.FirewallRuleID)
			if err != nil {
				if !provider.IsErrNotFound(err) {
					log.Error(err, "Failed to delete firewall rule", "firewallRuleID", *rule.Status.FirewallRuleID)
					return ctrl.Result{}, err
				}
				log.V(1).Info("Firewall rule already deleted", "firewallRuleID", *rule.Status.FirewallRuleID)
			} else {
				log.Info("Deleted firewall rule", "firewallRuleID", *rule.Status.FirewallRuleID)
			}
		}
	}

	// Update status
	rule.Status = v1alpha1.FirewallRuleStatus{State: v1alpha1.FirewallRuleStateNone}
	log.V(1).Info("Updating FirewallRule", "state", rule.Status.State)
	if err := r.Status().Update(ctx, rule); err != nil {
		log.Error(err, "Failed to update FirewallRule state", "firewallRule", rule.Name)
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *FirewallRuleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Index FirewallRule NodeName to list FirewallRules by node.
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &v1alpha1.FirewallRule{}, firewallRuleNodeNameKey, func(o client.Object) []string {
		fr := o.(*v1alpha1.FirewallRule)
		return []string{helper.StringValue(fr.Spec.NodeName)}
	}); err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.FirewallRule{}).
		Complete(r)
}

// encodeCreateFirewallRuleGroupRequest converts an api FirewallRule slice to a CreateFirewallRuleGroupRequest slice.
func encodeCreateFirewallRuleGroupRequest(name, description string, data []v1alpha1.FirewallRule) provider.CreateFirewallRuleGroupRequest {
	return provider.CreateFirewallRuleGroupRequest{
		Name:          name,
		Description:   description,
		FirewallRules: encodeFirewallRuleSpecs(data),
	}
}

// encodeCreateFirewallRuleRequest converts an api FirewallRule to a CreateFirewallRuleRequest.
func encodeCreateFirewallRuleRequest(data *v1alpha1.FirewallRule) provider.CreateFirewallRuleRequest {
	return provider.CreateFirewallRuleRequest{
		FirewallRuleSpec: encodeFirewallRuleSpec(data),
	}
}

// encodeUpdateFirewallRuleGroupRequest converts an api FirewallRule slice to a UpdateFirewallRuleGroupRequest slice.
func encodeUpdateFirewallRuleGroupRequest(id string, data []v1alpha1.FirewallRule) provider.UpdateFirewallRuleGroupRequest {
	return provider.UpdateFirewallRuleGroupRequest{
		FirewallRuleGroupID: id,
		FirewallRules:       encodeFirewallRuleSpecs(data),
	}
}

// encodeUpdateFirewallRuleRequest converts an api FirewallRule to a UpdateFirewallRuleRequest.
func encodeUpdateFirewallRuleRequest(id string, data *v1alpha1.FirewallRule) provider.UpdateFirewallRuleRequest {
	return provider.UpdateFirewallRuleRequest{
		FirewallRuleID:   id,
		FirewallRuleSpec: encodeFirewallRuleSpec(data),
	}
}

// encodeFirewallRuleSpecs converts an api FirewallRule slice to a FirewallRuleSpec slice.
func encodeFirewallRuleSpecs(data []v1alpha1.FirewallRule) []provider.FirewallRuleSpec {
	if data == nil {
		return make([]provider.FirewallRuleSpec, 0)
	}

	res := make([]provider.FirewallRuleSpec, len(data))
	for i, e := range data {
		res[i] = encodeFirewallRuleSpec(&e)
	}
	return res
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
