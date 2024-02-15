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
	"time"

	"github.com/go-logr/logr"
	"github.com/google/uuid"
	"github.com/quortex/kubestatic/api/v1alpha1"
	"github.com/quortex/kubestatic/pkg/helper"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/selection"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

const (
	// externalIPAutoAssignLabel is the key for auto externalIP assignment label
	externalIPAutoAssignLabel = "kubestatic.quortex.io/externalip-auto-assign"
	// externalIPLabel is the key for auto externalIP label (the externalIP a pod should have)
	externalIPLabel = "kubestatic.quortex.io/externalip"
	// Minimum time to wait between two reconciliations for the same node
	minReconciliationInterval = 10 * time.Second
	// The time for which nodes are automatically reconciled
	reconciliationRequeueInterval = 1 * time.Minute
)

// NodeReconciler reconciles a Node object
type NodeReconciler struct {
	client.Client
	Log                    logr.Logger
	Scheme                 *runtime.Scheme
	PreventEIPDeallocation bool
	lastReconciliation     map[string]time.Time
}

//+kubebuilder:rbac:groups=core,resources=nodes,verbs=get;list;watch;update;patch
//+kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch
//+kubebuilder:rbac:groups=kubestatic.quortex.io,resources=externalips,verbs=get;list;watch;create;update;patch;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *NodeReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("node", req.NamespacedName, "reconciliationID", uuid.New().String())

	log.V(1).Info("Node reconciliation started")
	defer log.V(1).Info("Node reconciliation done")

	node := &corev1.Node{}
	if err := r.Get(ctx, req.NamespacedName, node); err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Return and don't requeue
			log.Info("ExternalIP resource not found. Ignoring since object must be deleted")
			delete(r.lastReconciliation, req.Name)
			return ctrl.Result{}, nil
		}
		// Error reading the object - requeue the request.
		log.Error(err, "Failed to get Node")
		return ctrl.Result{}, err
	}

	// Store reconciliation time to handle reconciliation interval
	r.lastReconciliation[req.Name] = time.Now()

	// List auto assigned ExternalIPs for reconciled node
	log.V(1).Info("List all ExternalIPs for node")
	externalIPs := &v1alpha1.ExternalIPList{}
	if err := r.Client.List(
		ctx,
		externalIPs,
	); err != nil {
		log.Error(err, "Unable to list ExternalIP resources", "nodeName", req.Name)
		return ctrl.Result{}, err
	}

	// Check for existing eip and filter orphaned ones
	orphanedEIPs := []v1alpha1.ExternalIP{}
	for _, eip := range externalIPs.Items {
		if eip.Labels[externalIPAutoAssignLabel] != "true" {
			continue
		}
		// Already existing ExternalIPs for this node, end reconciliation
		if eip.Spec.NodeName == req.Name {
			log.V(1).Info("Already associated ExternalIP, aborting")
			return ctrl.Result{RequeueAfter: reconciliationRequeueInterval}, nil
		}
		if eip.Spec.NodeName == "" {
			orphanedEIPs = append(orphanedEIPs, eip)
		}
	}

	// Some orphaned auto assigned ExternalIPs, check which one to reuse
	if len(orphanedEIPs) > 0 {
		// List pods that should be scheduled on orphaned ExternalIPs
		publicIPAddresses := publicIPAddresses(orphanedEIPs)

		requirement, err := labels.NewRequirement(externalIPLabel, selection.In, publicIPAddresses)
		if err != nil {
			log.Error(err, "Unable to compute selector")
			return ctrl.Result{}, err
		}
		sel := labels.NewSelector().Add(*requirement)

		log.V(1).Info("List all Pods with selector", "selector", sel)
		podList := &corev1.PodList{}
		if err := r.Client.List(ctx, podList, client.MatchingLabelsSelector{Selector: sel}); err != nil {
			log.Error(err, "Failed to list all Pods with selector", "selector", sel)
			return ctrl.Result{}, err
		}

		// We get the most referenced ExternalIP ore reuse the first one arbitrarily
		externalIP := getMostReferencedIP(podList.Items, orphanedEIPs)
		if externalIP == nil {
			externalIP = &orphanedEIPs[0]
			log.V(1).Info("No used ExternalIP found, fallback on using the first")
		}
		externalIP.Spec.NodeName = req.Name
		log.V(1).Info("Associating ExternalIP to node", "externalIP", externalIP.Name)
		if err := r.Update(ctx, externalIP); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: reconciliationRequeueInterval}, nil
	}

	// No ExternalIP to reuse, creating a new one.
	log.Info("Creating ExternalIP for node auto-assign")
	externalIP := &v1alpha1.ExternalIP{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "auto-assigned-",
			Labels:       map[string]string{externalIPAutoAssignLabel: "true"},
		},
		Spec: v1alpha1.ExternalIPSpec{
			NodeName:               req.Name,
			PreventEIPDeallocation: r.PreventEIPDeallocation,
		},
	}
	if err := r.Create(ctx, externalIP); err != nil {
		log.Error(err, "Unable to create ExternalIP")
		return ctrl.Result{}, err
	}

	return ctrl.Result{RequeueAfter: reconciliationRequeueInterval}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *NodeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.lastReconciliation = map[string]time.Time{}
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Node{}, r.nodeReconciliationPredicates()).
		Complete(r)
}

// nodeReconciliationPredicates returns predicates for the controller reconciliation configuration.
func (r *NodeReconciler) nodeReconciliationPredicates() builder.Predicates {
	return builder.WithPredicates(predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			return r.shouldReconcileNode(e.Object.(*corev1.Node))
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return r.shouldReconcileNode(e.Object.(*corev1.Node))
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			return r.shouldReconcileNode(e.ObjectNew.(*corev1.Node)) || r.shouldReconcileNode(e.ObjectOld.(*corev1.Node))
		},
	})
}

// shouldReconcileNode returns if given Node should be reconciled by the controller.
func (r *NodeReconciler) shouldReconcileNode(obj *corev1.Node) bool {
	// We should consider reconciliation for nodes with automatic IP assignment label.
	if !helper.ContainsElements(obj.ObjectMeta.Labels, map[string]string{externalIPAutoAssignLabel: "true"}) {
		return false
	}

	// In the case of close consecutive reconciliations for the same Node, if an
	// ExternalIP is created for this node the cached ExternalIP list may not have been
	// notified of the fact that there is a new ExternalIP when the following
	// reconciliation for this Node occurs.
	// This can lead to the creation of unwanted ExternalIPs for this Node.
	// Prevent frequent reconciliations is a workaround to ensure that the list of
	// cached ExternalIPs is the correct one.
	lastRec, ok := r.lastReconciliation[obj.Name]
	if ok && time.Since(lastRec) < minReconciliationInterval {
		return false
	}
	return true
}
