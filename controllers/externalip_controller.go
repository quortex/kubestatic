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

	"github.com/go-logr/logr"
	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/quortex/kubestatic/api/v1alpha1"
	"github.com/quortex/kubestatic/pkg/helper"
	"github.com/quortex/kubestatic/pkg/provider"
)

const (
	// externalIPFinalizer is a finalizer for ExternalIP
	externalIPFinalizer = "externalip.finalizers.kubestatic.quortex.io"
)

// ExternalIPReconciler reconciles a ExternalIP object
type ExternalIPReconciler struct {
	client.Client
	Log      logr.Logger
	Scheme   *runtime.Scheme
	Provider provider.Provider
}

//+kubebuilder:rbac:groups=kubestatic.quortex.io,resources=externalips,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=kubestatic.quortex.io,resources=externalips/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=kubestatic.quortex.io,resources=externalips/finalizers,verbs=update
//+kubebuilder:rbac:groups=core,resources=nodes,verbs=get;list;watch;update;patch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *ExternalIPReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("externalip", req.NamespacedName, "reconciliationID", uuid.New().String())

	log.V(1).Info("ExternalIP reconciliation started")
	defer log.V(1).Info("ExternalIP reconciliation done")

	externalIP := &v1alpha1.ExternalIP{}
	if err := r.Get(ctx, req.NamespacedName, externalIP); err != nil {
		if errors.IsNotFound(err) {
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
		log.Info("Reconciliation externalIpdisabled")
		return ctrl.Result{}, nil
	}

	// Lifecycle reconciliation
	if externalIP.ObjectMeta.DeletionTimestamp.IsZero() {
		return r.reconcileExternalIP(ctx, log, externalIP)
	}

	// Deletion reconciliation
	return r.reconcileExternalIPDeletion(ctx, log, externalIP)
}

func (r *ExternalIPReconciler) reconcileExternalIP(ctx context.Context, log logr.Logger, externalIP *v1alpha1.ExternalIP) (ctrl.Result, error) {
	// 1st STEP
	//
	// Add finalizer
	if !helper.ContainsString(externalIP.ObjectMeta.Finalizers, externalIPFinalizer) {
		externalIP.ObjectMeta.Finalizers = append(externalIP.ObjectMeta.Finalizers, externalIPFinalizer)
		log.V(1).Info("Updating ExternalIP", "finalizer", externalIPFinalizer)
		return ctrl.Result{}, r.Update(ctx, externalIP)
	}

	// 2nd STEP
	//
	// Reserve external IP address
	if externalIP.Status.State == v1alpha1.ExternalIPStateNone {
		// Create external address
		res, err := r.Provider.CreateAddress(ctx)
		if err != nil {
			log.Error(err, "Failed to create address")
			return ctrl.Result{}, err
		}
		log.Info("Created address", "id", res.AddressID, "publicIP", res.PublicIP)

		// Update status
		externalIP.Status.State = v1alpha1.ExternalIPStateReserved
		externalIP.Status.AddressID = &res.AddressID
		externalIP.Status.PublicIPAddress = &res.PublicIP
		log.V(1).Info("Updating ExternalIP", "state", externalIP.Status.State, "addressID", externalIP.Status.AddressID, "PublicIPAddress", externalIP.Status.PublicIPAddress)
		return ctrl.Result{}, r.Status().Update(ctx, externalIP)
	}

	// 3rd STEP
	//
	// Finally associate external ip to instance network interface.
	// This must be the last step, since this exposes the instance on the outside.
	if externalIP.IsReserved() {
		if externalIP.Spec.NodeName != "" {
			// Get node from ExternalIP spec
			var node corev1.Node
			if err := r.Get(ctx, types.NamespacedName{Name: externalIP.Spec.NodeName}, &node); err != nil {
				if errors.IsNotFound(err) {
					// Invalid nodeName, remove ExternalIP nodeName attribute.
					log.Info("Node not found. Removing it from ExternalIP spec", "nodeName", externalIP.Spec.NodeName)
					externalIP.Spec.NodeName = ""
					return ctrl.Result{}, r.Update(ctx, externalIP)
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

			// Interface with index 0 is the first attached to node, the one we're interested in.
			// Each instance has a default network interface, called the primary network interface.
			// You cannot detach a primary network interface from an instance.
			var networkInterface *provider.NetworkInterface
			for _, elem := range res.NetworkInterfaces {
				if elem != nil && *elem.DeviceID == 0 {
					networkInterface = elem
					break
				}
			}
			if networkInterface == nil {
				err := fmt.Errorf("no network interface with public IP found for instance %s", instanceID)
				log.Error(err, "Cannot associate an address with this instance", "instanceID", instanceID)
				return ctrl.Result{}, err
			}

			// Finally, associate address to instance network interface, then update status.
			if err := r.Provider.AssociateAddress(ctx, provider.AssociateAddressRequest{
				AddressID:          *externalIP.Status.AddressID,
				NetworkInterfaceID: networkInterface.NetworkInterfaceID,
			}); err != nil {
				log.Error(err, "Failed to associate address", "addressID", *externalIP.Status.AddressID, "instanceID", instanceID, "networkInterfaceID", networkInterface.NetworkInterfaceID)
				return ctrl.Result{}, err
			}
			log.Info("Associated address", "addressID", *externalIP.Status.AddressID, "instanceID", instanceID, "networkInterfaceID", networkInterface.NetworkInterfaceID)

			// Update status
			externalIP.Status.State = v1alpha1.ExternalIPStateAssociated
			externalIP.Status.InstanceID = &instanceID
			log.V(1).Info("Updating ExternalIP", "state", externalIP.Status.State, "InstanceID", externalIP.Status.InstanceID)
			return ctrl.Result{}, r.Status().Update(ctx, externalIP)
		}

		// No spec.nodeName, no association, end reconciliation for ExternalIP.
		log.V(1).Info("No No spec.nodeName, no association, end reconciliation for ExternalIP.")
		return ctrl.Result{}, nil
	}

	// ExternalIP reliability check
	//
	// Check if the associated node still exists and disassociate it if it does not.
	// No nodeName or no living node, set state back to "Reserved"
	if externalIP.IsAssociated() {
		if externalIP.Spec.NodeName != "" {
			// Get node from ExternalIP spec
			var node corev1.Node
			if err := r.Get(ctx, types.NamespacedName{Name: externalIP.Spec.NodeName}, &node); err != nil {
				if errors.IsNotFound(err) {
					// Invalid nodeName, remove ExternalIP nodeName attribute.
					log.Info("Node not found. Removing it from ExternalIP spec", "nodeName", externalIP.Spec.NodeName)

					// Set status back to Reserved
					externalIP.Status.State = v1alpha1.ExternalIPStateReserved
					log.V(1).Info("Updating ExternalIP", "state", externalIP.Status.State, "InstanceID", externalIP.Status.InstanceID)
					if err = r.Status().Update(ctx, externalIP); err != nil {
						log.Error(err, "Failed to update ExternalIP status", "externalIP", externalIP.Name, "status", externalIP.Status.State)
						return ctrl.Result{}, err
					}

					externalIP.Spec.NodeName = ""
					return ctrl.Result{}, r.Update(ctx, externalIP)
				}
				// Error reading the object - requeue the request.
				log.Error(err, "Failed to get Node")
				return ctrl.Result{}, err
			}

			// Node not being deleted, reconcile externalip label
			if node.ObjectMeta.DeletionTimestamp.IsZero() {
				// Marshal node, ...
				old, err := json.Marshal(node)
				if err != nil {
					log.Error(err, "Failed to marshal node")
					return ctrl.Result{}, err
				}

				// ... then compute new node to marshal it...
				node.Labels[externalIPLabel] = *externalIP.Status.PublicIPAddress
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

				return ctrl.Result{}, nil
			}
		}

		// Set state back to "Reserved", disassociate address and end reconciliation
		return r.disassociateAddress(ctx, r.Provider, log, externalIP)
	}

	return ctrl.Result{}, nil
}

func (r *ExternalIPReconciler) reconcileExternalIPDeletion(ctx context.Context, log logr.Logger, externalIP *v1alpha1.ExternalIP) (ctrl.Result, error) {
	// 1st STEP
	//
	// Reconciliation of a possible external IP associated with the instance.
	// If an IP is associated with the instance, disassociate it.
	if externalIP.IsAssociated() {
		return r.disassociateAddress(ctx, r.Provider, log, externalIP)
	}

	// 2nd STEP
	//
	// Release unassociated address.
	if externalIP.IsReserved() {
		if err := r.Provider.DeleteAddress(ctx, *externalIP.Status.AddressID); err != nil {
			if !provider.IsErrNotFound(err) {
				log.Error(err, "Failed to delete Address", "addressID", *externalIP.Status.AddressID)
				return ctrl.Result{}, err
			}
			log.V(1).Info("Address not found", "addressID", *externalIP.Status.AddressID)
		}
		log.Info("Deleted Address", "addressID", *externalIP.Status.AddressID)

		// Update status
		externalIP.Status.State = v1alpha1.ExternalIPStateNone
		externalIP.Status.AddressID = nil
		log.V(1).Info("Updating ExternalIP", "state", externalIP.Status.State)
		return ctrl.Result{}, r.Status().Update(ctx, externalIP)
	}

	// 3rd STEP
	//
	// Remove finalizer to release ExternalIP
	if externalIP.Status.State == v1alpha1.ExternalIPStateNone {
		if helper.ContainsString(externalIP.Finalizers, externalIPFinalizer) {
			externalIP.Finalizers = helper.RemoveString(externalIP.Finalizers, externalIPFinalizer)
			return ctrl.Result{}, r.Update(ctx, externalIP)
		}
	}

	return ctrl.Result{}, nil
}

// disassociateAddress performs address disassociation tasks
func (r *ExternalIPReconciler) disassociateAddress(ctx context.Context, pvd provider.Provider, log logr.Logger, externalIP *v1alpha1.ExternalIP) (ctrl.Result, error) {
	// Get address and disassociate it
	if externalIP.Status.AddressID != nil {
		res, err := pvd.GetAddress(ctx, *externalIP.Status.AddressID)
		if err != nil {
			log.Error(err, "Failed to retrieve address", "addressID", *externalIP.Status.AddressID)
			return ctrl.Result{}, err
		}

		if res.AssociationID != nil {
			if err := pvd.DisassociateAddress(ctx, provider.DisassociateAddressRequest{
				AssociationID: *res.AssociationID,
			}); err != nil {
				log.Error(err, "Failed to disassociate address", "addressID", *externalIP.Status.AddressID, "instanceID", *externalIP.Status.InstanceID)
				return ctrl.Result{}, err
			}
			log.Info("Disassociated address", "addressID", *externalIP.Status.AddressID, "instanceID", *externalIP.Status.InstanceID)
		}
	}

	// Update status
	externalIP.Status.State = v1alpha1.ExternalIPStateReserved
	externalIP.Status.InstanceID = nil
	log.V(1).Info("Updating ExternalIP", "state", externalIP.Status.State)
	if err := r.Status().Update(ctx, externalIP); err != nil {
		log.Error(err, "Failed to update ExternalIP state", "externalIP", externalIP.Name)
		return ctrl.Result{}, err
	}

	log.V(1).Info("Removing ExternalIP NodeName", "externalIP", externalIP.Name)
	externalIP.Spec.NodeName = ""
	return ctrl.Result{}, r.Update(ctx, externalIP)
}

// SetupWithManager sets up the controller with the Manager.
func (r *ExternalIPReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.ExternalIP{}).
		Watches(
			&source.Kind{Type: &corev1.Node{}},
			handler.EnqueueRequestsFromMapFunc(func(o client.Object) []reconcile.Request {
				ctx := context.Background()
				log := r.Log.WithName("nodemapper")
				node := o.(*corev1.Node)

				// List ExternalIPs that matches node name
				log.V(1).Info("List all ExternalIP for node")
				externalIPs := &v1alpha1.ExternalIPList{}
				if err := r.Client.List(ctx, externalIPs, client.MatchingFields{externalIPNodeNameField: node.Name}); err != nil {
					log.Error(err, "Unable to list ExternalIP resources", "nodeName", node.Name)
					return []reconcile.Request{}
				}

				// Reconcile each matching ExternalIP
				res := make([]reconcile.Request, len(externalIPs.Items))
				for i, e := range externalIPs.Items {
					res[i] = reconcile.Request{NamespacedName: types.NamespacedName{Name: e.Name}}
				}
				return res
			}),
		).
		Complete(r)
}
