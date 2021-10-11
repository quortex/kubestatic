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
	"fmt"
	"strings"

	"github.com/go-logr/logr"
	"github.com/google/uuid"
	"github.com/quortex/kubestatic/api/v1alpha1"
	"github.com/quortex/kubestatic/pkg/helper"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
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
	// externalIPNodeNameField is the nodeName field in ExternalIP resource
	externalIPNodeNameField = ".spec.nodeName"
)

// NodeReconciler reconciles a Node object
type NodeReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=core,resources=nodes,verbs=get;list;watch;update;patch
//+kubebuilder:rbac:groups=kubestatic.quortex.io,resources=externalips,verbs=get;list;watch;create;update;patch;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *NodeReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("node", req.NamespacedName, "reconciliationID", uuid.New().String())

	log.V(1).Info("Node reconciliation started")
	defer log.V(1).Info("Node reconciliation done")

	// List auto assigned ExternalIPs for reconciled node
	log.V(1).Info("List all ExternalIPs for node")
	externalIPs := &v1alpha1.ExternalIPList{}
	if err := r.Client.List(
		ctx,
		externalIPs,
		client.MatchingFields{externalIPNodeNameField: req.Name},
		client.MatchingLabels{externalIPAutoAssignLabel: "true"},
	); err != nil {
		log.Error(err, "Unable to list ExternalIP resources", "nodeName", req.Name)
		return ctrl.Result{}, err
	}

	// Already existing ExternalIPs for this node, end reconciliation
	if len(externalIPs.Items) > 0 {
		log.V(1).Info("Already associated ExternalIP, aborting")
		return ctrl.Result{}, nil
	}

	// List orphaned auto assigned ExternalIPs to reuse it
	log.V(1).Info("Listing orphaned auto assigned ExternalIPs")
	if err := r.Client.List(
		ctx,
		externalIPs,
		client.MatchingFields{externalIPNodeNameField: ""},
		client.MatchingLabels{externalIPAutoAssignLabel: "true"},
	); err != nil {
		log.Error(err, "Unable to list ExternalIP resources", "nodeName", "")
		return ctrl.Result{}, err
	}

	// Some orphaned auto assigned ExternalIPs, check which one to reuse
	if len(externalIPs.Items) > 0 {
		// List pods that should be scheduled on orphaned ExternalIPs
		publicIPAddresses := publicIPAddresses(externalIPs.Items)
		lblValue := fmt.Sprintf("in (%s)", strings.Join(publicIPAddresses, ","))
		log.V(1).Info("List all Pods with labels", "key", externalIPLabel, "value", lblValue)
		podList := &corev1.PodList{}
		if err := r.Client.List(
			ctx,
			podList,
			client.MatchingLabels{externalIPAutoAssignLabel: lblValue},
		); err != nil {
			log.Error(err, "List all Pods with labels", "key", externalIPLabel, "value", lblValue)
			return ctrl.Result{}, err
		}

		// We get the most referenced ExternalIP ore reuse the first one arbitrarily
		externalIP := getMostReferencedIP(podList.Items, externalIPs.Items)
		if externalIP == nil {
			externalIP = &externalIPs.Items[0]
		}
		externalIP.Spec.NodeName = req.Name
		log.V(1).Info("Associating ExternalIP to node", "externalIP", externalIP.Name)
		return ctrl.Result{}, r.Update(ctx, externalIP)
	}

	// No ExternalIP to reuse, creating a new one.
	log.Info("Creating ExternalIP for node auto-assign")
	externalIP := &v1alpha1.ExternalIP{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "auto-assigned-",
			Labels:       map[string]string{externalIPAutoAssignLabel: "true"},
		},
		Spec: v1alpha1.ExternalIPSpec{
			NodeName: req.Name,
		},
	}
	if err := r.Create(ctx, externalIP); err != nil {
		log.Error(err, "Unable to create ExternalIP")
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *NodeReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Index ExternalIP NodeName to list only ExternalIPs assigned to Node.
	_ = mgr.GetCache().IndexField(context.TODO(), &v1alpha1.ExternalIP{}, externalIPNodeNameField, func(o client.Object) []string {
		externalIP := o.(*v1alpha1.ExternalIP)
		return []string{externalIP.Spec.NodeName}
	})

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
	return helper.ContainsElements(obj.ObjectMeta.Labels, map[string]string{externalIPAutoAssignLabel: "true"})
}
