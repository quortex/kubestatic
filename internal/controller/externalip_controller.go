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
	"encoding/json"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/quortex/kubestatic/api/v1alpha1"
	"github.com/quortex/kubestatic/internal/provider"
)

const (
	// externalIPFinalizer is a finalizer for ExternalIP
	externalIPFinalizer = "externalip.finalizers.kubestatic.quortex.io"
)

// ExternalIPReconciler reconciles a ExternalIP object
type ExternalIPReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Provider provider.Provider
}

// +kubebuilder:rbac:groups=kubestatic.quortex.io,resources=externalips,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=kubestatic.quortex.io,resources=externalips/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=kubestatic.quortex.io,resources=externalips/finalizers,verbs=update
// +kubebuilder:rbac:groups=core,resources=nodes,verbs=get;list;watch;update;patch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *ExternalIPReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)
	log.V(1).Info("ExternalIP reconciliation started")

	externalIP := &v1alpha1.ExternalIP{}
	if err := r.Get(ctx, req.NamespacedName, externalIP); err != nil {
		if apierrors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Return and don't requeue
			log.Info("ExternalIP resource not found. Ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		// Error reading the object - requeue the request.
		log.Error(err, "Failed to get ExternalIP")
		return ctrl.Result{}, err
	}

	if externalIP.Spec.DisableReconciliation {
		log.Info("Reconciliation disabled")
		return ctrl.Result{}, nil
	}

	// Add finalizer
	if !controllerutil.ContainsFinalizer(externalIP, externalIPFinalizer) {
		externalIP.ObjectMeta.Finalizers = append(externalIP.ObjectMeta.Finalizers, externalIPFinalizer)
		if err := r.Update(ctx, externalIP); err != nil {
			log.Error(err, "Failed to add finalizer")
			return ctrl.Result{}, err
		}
		log.V(1).Info("Successfully added finalizer")
		return ctrl.Result{}, nil
	}

	// Get node from ExternalIP spec
	var node corev1.Node
	var instanceID string
	if externalIP.Spec.NodeName != "" {
		if err := r.Get(ctx, types.NamespacedName{Name: externalIP.Spec.NodeName}, &node); err != nil {
			if apierrors.IsNotFound(err) {
				// Invalid nodeName, remove ExternalIP nodeName attribute.
				externalIP.Spec.NodeName = ""
				if err != r.Update(ctx, externalIP) {
					log.Error(err, "Failed to remove nodeName from ExternalIP spec", "nodeName", externalIP.Spec.NodeName)
					return ctrl.Result{}, err
				}
				log.Info("Node not found. Removing it from ExternalIP spec", "nodeName", externalIP.Spec.NodeName)
				return ctrl.Result{}, nil
			}
			// Error reading the object - requeue the request.
			log.Error(err, "Failed to get Node")
			return ctrl.Result{}, err
		}
		// Retrieve node instance
		instanceID = r.Provider.GetInstanceID(node)
	}

	var status v1alpha1.ExternalIPStatus
	var err error
	if externalIP.ObjectMeta.DeletionTimestamp.IsZero() {
		status, err = r.Provider.ReconcileExternalIP(ctx, log, instanceID, externalIP)
		if err != nil {
			if patchErr := patchExternalIPStatus(ctx, r, externalIP, status); patchErr != nil {
				log.Error(errors.Join(patchErr, err), "Failed to patch ExternalIP status during error handling")
				return ctrl.Result{}, fmt.Errorf("failed to patch ExternalIP status during error handling: %w", errors.Join(patchErr, err))
			}
			log.Error(err, "Failed to reconcile ExternalIP")
			return ctrl.Result{}, err
		}
		// Node not being deleted, reconcile externalip label
		if externalIP.Spec.NodeName != "" && node.ObjectMeta.DeletionTimestamp.IsZero() {
			// Marshal node, ...
			old, err := json.Marshal(node)
			if err != nil {
				log.Error(err, "Failed to marshal node")
				return ctrl.Result{}, err
			}

			// ... then compute new node to marshal it...
			node.Labels[externalIPLabel] = *status.PublicIPAddress
			new, err := json.Marshal(node)
			if err != nil {
				log.Error(err, "Failed to marshal new node")
				return ctrl.Result{}, err
			}

			// ... and create a patch.
			patch, err := strategicpatch.CreateTwoWayMergePatch(old, new, node)
			if err != nil {
				log.Error(err, "Failed to create patch for node")
				return ctrl.Result{}, err
			}

			// Apply patch to set node's wanted labels.
			if err = r.Client.Patch(ctx, &node, client.RawPatch(types.MergePatchType, patch)); err != nil {
				log.Error(err, "Failed to patch node")
				return ctrl.Result{}, err
			}
		}
	} else {
		if err := r.Provider.ReconcileExternalIPDeletion(ctx, log, externalIP); err != nil {
			log.Error(err, "Failed to reconcile ExternalIP deletion")
			return ctrl.Result{}, err
		}
	}

	if !externalIP.DeletionTimestamp.IsZero() && controllerutil.ContainsFinalizer(externalIP, externalIPFinalizer) {
		controllerutil.RemoveFinalizer(externalIP, externalIPFinalizer)
		if err := r.Update(ctx, externalIP); err != nil {
			log.Error(err, "Failed to remove finalizer")
			return ctrl.Result{}, err
		}
		log.V(1).Info("Successfully removed finalizer")
		return ctrl.Result{}, nil
	}

	if err := patchExternalIPStatus(ctx, r, externalIP, status); err != nil {
		log.Error(err, "Failed to patch ExternalIP status")
		return ctrl.Result{}, fmt.Errorf("failed to patch ExternalIP status: %w", err)
	}

	log.Info("ExternalIP successfully reconciled")

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ExternalIPReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.ExternalIP{}).
		Watches(
			&corev1.Node{},
			handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) []reconcile.Request {
				log := mgr.GetLogger().WithName("nodemapper")
				node := o.(*corev1.Node)

				log.V(1).Info("List all ExternalIP")
				externalIPs := &v1alpha1.ExternalIPList{}
				if err := r.Client.List(ctx, externalIPs); err != nil {
					log.Error(err, "Unable to list ExternalIP resources", "nodeName", node.Name)
					return []reconcile.Request{}
				}

				// Reconcile each matching ExternalIP
				res := []reconcile.Request{}
				for _, eip := range externalIPs.Items {
					if eip.Spec.NodeName == node.Name {
						res = append(res, reconcile.Request{NamespacedName: types.NamespacedName{Name: eip.Name}})
					}
				}
				return res
			}),
		).
		Complete(r)
}

// patchExternalIPStatus updates the status of a ExternalIP resource if there are any changes.
// It patches the status with the new status provided and updates the LastTransitionTime if there are differences.
//
// Parameters:
//
//	ctx - The context for the request.
//	r - The ExternalIPReconciler responsible for reconciling the ExternalIP resource.
//	externalIP - The ExternalIP resource to be updated.
//	newStatus - The new status to be applied to the ExternalIP resource.
//
// Returns:
//
//	error - An error if the patch operation fails, otherwise nil.
func patchExternalIPStatus(
	ctx context.Context,
	r *ExternalIPReconciler,
	externalIP *v1alpha1.ExternalIP,
	newStatus v1alpha1.ExternalIPStatus,
) error {
	existingEIP := externalIP.DeepCopy()
	externalIP.Status = newStatus

	if !equality.Semantic.DeepEqual(externalIP.Status, existingEIP.Status) {
		if err := r.Status().Patch(ctx, externalIP, client.MergeFrom(existingEIP)); err != nil {
			return err
		}
	}
	return nil
}
