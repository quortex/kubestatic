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

package controller

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/quortex/kubestatic/api/v1alpha1"
	"github.com/quortex/kubestatic/internal/provider"
)

const (
	annNodeName = "kubestatic.quortex.io/node-name"

	// firewallRuleFinalizer is a finalizer for FirewallRule
	firewallRuleFinalizer   = "firewallrule.finalizers.kubestatic.quortex.io"
	firewallRuleNodeNameKey = ".spec.nodeName"
)

// FirewallRuleReconciler reconciles a FirewallRule object
type FirewallRuleReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Provider provider.Provider
}

// +kubebuilder:rbac:groups=kubestatic.quortex.io,resources=firewallrules,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=kubestatic.quortex.io,resources=firewallrules/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=kubestatic.quortex.io,resources=firewallrules/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *FirewallRuleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	log.Info("FirewallRule reconciliation started")

	firewallRule := &v1alpha1.FirewallRule{}
	if err := r.Get(ctx, req.NamespacedName, firewallRule); err != nil {
		if apierrors.IsNotFound(err) {
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

	if firewallRule.Spec.NodeName == nil {
		log.V(1).Info("No nodename found on the FirewallRule")
		return ctrl.Result{}, nil
	}

	// Add finalizer
	if !controllerutil.ContainsFinalizer(firewallRule, firewallRuleFinalizer) {
		firewallRule.ObjectMeta.Finalizers = append(firewallRule.ObjectMeta.Finalizers, firewallRuleFinalizer)
		if err := r.Update(ctx, firewallRule); err != nil {
			log.Error(err, "Failed to add finalizer")
			return ctrl.Result{}, err
		}
		log.V(1).Info("Successfully added finalizer")
		return ctrl.Result{}, nil
	}

	previousNodeName := firewallRule.Annotations[annNodeName]
	currentNodeName := ptr.Deref(firewallRule.Spec.NodeName, "")

	// Initial creation or previous node name has been reconciled,
	// reconcile FirewallRules for the current node and update the
	// FirewallRule with the node annotation
	if previousNodeName == "" && currentNodeName != "" {
		if err := r.reconcileNodeFirewallRules(ctx, log, currentNodeName); err != nil {
			log.Error(err, "Failed to reconcile node FirewallRules")
			return ctrl.Result{}, err
		}

		existingFR := client.MergeFrom(firewallRule.DeepCopy())
		if firewallRule.Annotations == nil {
			firewallRule.Annotations = make(map[string]string, 1)
		}
		firewallRule.Annotations[annNodeName] = currentNodeName

		if err := r.Client.Patch(ctx, firewallRule, existingFR); err != nil {
			log.Error(err, "Failed to add annotation node name")
			return ctrl.Result{}, err
		}
		log.V(1).Info("Successfully added annotation node name")
		return ctrl.Result{}, nil
	}

	// Node name has changed, reconcile FirewallRules for the previous node,
	// then update the FirewallRule to remove the node annotation
	if previousNodeName != "" && currentNodeName != previousNodeName {
		if err := r.reconcileNodeFirewallRules(ctx, log, previousNodeName); err != nil {
			log.Error(err, "Failed to reconcile node FirewallRules")
			return ctrl.Result{}, err
		}

		existingFR := client.MergeFrom(firewallRule.DeepCopy())
		delete(firewallRule.Annotations, annNodeName)
		if err := r.Client.Patch(ctx, firewallRule, existingFR); err != nil {
			log.Error(err, "Failed to remove annotation node name")
			return ctrl.Result{}, err
		}
		log.V(1).Info("Successfully removed annotation node name")
		return ctrl.Result{}, nil
	}

	// Node name has not changed, reconcile FirewallRules for the current node
	if previousNodeName != "" && currentNodeName == previousNodeName {
		if err := r.reconcileNodeFirewallRules(ctx, log, currentNodeName); err != nil {
			log.Error(err, "Failed to reconcile node FirewallRules")
			return ctrl.Result{}, err
		}
	}

	// Remove finalizer
	if !firewallRule.DeletionTimestamp.IsZero() && controllerutil.ContainsFinalizer(firewallRule, firewallRuleFinalizer) {
		controllerutil.RemoveFinalizer(firewallRule, firewallRuleFinalizer)
		if err := r.Update(ctx, firewallRule); err != nil {
			log.Error(err, "Failed to remove finalizer")
			return ctrl.Result{}, err
		}
		log.V(1).Info("Successfully removed finalizer")
	}

	log.Info("FirewallRule successfully reconciled")

	return ctrl.Result{}, nil
}

// reconcileNodeFirewallRules reconciles the firewall rules for a specific node.
// It lists all FirewallRule resources associated with the given node and filters out those that are marked for deletion.
// If no active firewall rules are found, it triggers the deletion of firewall rules on the provider side.
// Otherwise, it reconciles the existing firewall rules.
//
// Parameters:
//   - ctx: The context for the reconciliation process.
//   - log: The logger used for logging messages.
//   - nodeName: The name of the node for which firewall rules are being reconciled.
//
// Returns:
//   - error: An error if the reconciliation process fails, otherwise nil.
func (r *FirewallRuleReconciler) reconcileNodeFirewallRules(
	ctx context.Context,
	log logr.Logger,
	nodeName string,
) error {
	var firewallRuleList v1alpha1.FirewallRuleList
	if err := r.List(ctx, &firewallRuleList, client.MatchingFields{firewallRuleNodeNameKey: nodeName}); err != nil {
		log.Error(err, "Unable to list FirewallRules")
		return err
	}

	firewallRuleList.Items = slices.DeleteFunc(firewallRuleList.Items, func(fr v1alpha1.FirewallRule) bool {
		return !fr.DeletionTimestamp.IsZero()
	})

	if len(firewallRuleList.Items) == 0 {
		if err := r.Provider.ReconcileFirewallRulesDeletion(ctx, log, nodeName); err != nil {
			log.Error(err, "Failed to reconcile FirewallRule deletion")
			return err
		}
	} else {
		if err := r.reconcileFirewallRules(ctx, log, nodeName, firewallRuleList.Items); err != nil {
			log.Error(err, "Failed to reconcile FirewallRules")
			return err
		}
	}

	return nil
}

// reconcileFirewallRules reconciles the firewall rules for a specific node.
// It retrieves the node information and updates the firewall rules accordingly.
// If the node is not found, it triggers the deletion of firewall rules on the provider side.
// Otherwise, it reconciles the existing firewall rules and updates their status.
//
// Parameters:
//   - ctx: The context for the reconciliation process.
//   - log: The logger used for logging messages.
//   - nodeName: The name of the node for which firewall rules are being reconciled.
//   - firewallRules: A list of FirewallRule resources to be reconciled.
//
// Returns:
//   - error: An error if the reconciliation process fails, otherwise nil.
func (r *FirewallRuleReconciler) reconcileFirewallRules(
	ctx context.Context,
	log logr.Logger,
	nodeName string,
	firewallRules []v1alpha1.FirewallRule,
) error {
	var node corev1.Node
	if err := r.Get(ctx, types.NamespacedName{Name: nodeName}, &node); err != nil {
		if apierrors.IsNotFound(err) {
			if err := r.Provider.ReconcileFirewallRulesDeletion(ctx, log, nodeName); err != nil {
				log.Error(err, "Failed to reconcile FirewallRule deletion")
				return err
			}
			return err
		}

		log.Error(err, "Failed to get Node")
		return err
	}

	status, conditions, err := r.Provider.ReconcileFirewallRules(ctx, log, nodeName, r.Provider.GetInstanceID(node), firewallRules)
	if err != nil {
		for _, fr := range firewallRules {
			for _, condition := range conditions {
				condition.ObservedGeneration = fr.Generation
				meta.SetStatusCondition(&status.Conditions, condition)
			}
			existingFR := fr.DeepCopy()
			fr.Status = status
			fr.Status.LastTransitionTime = existingFR.Status.LastTransitionTime
			if !reflect.DeepEqual(fr.Status, existingFR.Status) {
				fr.Status.LastTransitionTime = metav1.Now()
				patchErr := r.Status().Patch(ctx, &fr, client.MergeFrom(existingFR))
				if patchErr != nil {
					log.Error(errors.Join(patchErr, err), "Failed to patch FirewallRule status during error handling")
					return fmt.Errorf("failed to patch FirewallRule status during error handling: %w", errors.Join(patchErr, err))
				}
			}
		}
		log.Error(err, "Failed to reconcile FirewallRule")
		return err
	}

	for _, fr := range firewallRules {
		for _, condition := range conditions {
			meta.SetStatusCondition(&status.Conditions, condition)
			condition.ObservedGeneration = fr.GetGeneration()
		}
		existingFR := fr.DeepCopy()
		fr.Status = status
		fr.Status.LastTransitionTime = existingFR.Status.LastTransitionTime
		if !reflect.DeepEqual(fr.Status, existingFR.Status) {
			fr.Status.LastTransitionTime = metav1.Now()
			err := r.Status().Patch(ctx, &fr, client.MergeFrom(existingFR))
			if err != nil {
				log.Error(err, "Failed to patch FirewallRule status")
				return fmt.Errorf("failed to patch FirewallRule status: %w", err)
			}
		}
	}

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *FirewallRuleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &v1alpha1.FirewallRule{}, firewallRuleNodeNameKey, func(o client.Object) []string {
		fr := o.(*v1alpha1.FirewallRule)
		return []string{ptr.Deref(fr.Spec.NodeName, "")}
	}); err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.FirewallRule{}).
		Complete(r)
}
