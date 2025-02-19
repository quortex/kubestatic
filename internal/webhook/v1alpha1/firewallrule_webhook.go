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

package v1alpha1

import (
	"context"
	"fmt"
	"slices"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/quortex/kubestatic/api/v1alpha1"
	"github.com/quortex/kubestatic/internal/provider"
)

// log is for logging in this package.
var firewallrulelog = logf.Log.WithName("firewallrule-resource")

const firewallRuleNodeNameKey = ".spec.nodeName"

// SetupFirewallRuleWebhookWithManager registers the webhook for FirewallRule in the manager.
func SetupFirewallRuleWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).For(&v1alpha1.FirewallRule{}).
		WithValidator(&FirewallRuleCustomValidator{Client: mgr.GetClient()}).
		Complete()
}

// +kubebuilder:webhook:path=/validate-kubestatic-quortex-io-v1alpha1-firewallrule,mutating=false,failurePolicy=fail,sideEffects=None,groups=kubestatic.quortex.io,resources=firewallrules,verbs=create;update,versions=v1alpha1,name=vfirewallrule-v1alpha1.kb.io,admissionReviewVersions=v1

// FirewallRuleCustomValidator struct is responsible for validating the FirewallRule resource
// when it is created, updated, or deleted.
//
// NOTE: The +kubebuilder:object:generate=false marker prevents controller-gen from generating DeepCopy methods,
// as this struct is used only for temporary operations and does not need to be deeply copied.
type FirewallRuleCustomValidator struct {
	client.Client
}

var _ webhook.CustomValidator = &FirewallRuleCustomValidator{}

// ValidateCreate implements webhook.CustomValidator so a webhook will be registered for the type FirewallRule.
func (v *FirewallRuleCustomValidator) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	firewallrule, ok := obj.(*v1alpha1.FirewallRule)
	if !ok {
		return nil, fmt.Errorf("expected a FirewallRule object but got %T", obj)
	}
	firewallrulelog.Info("Validation for FirewallRule upon creation", "name", firewallrule.GetName())

	return v.validate(ctx, firewallrule)
}

// ValidateUpdate implements webhook.CustomValidator so a webhook will be registered for the type FirewallRule.
func (v *FirewallRuleCustomValidator) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	firewallrule, ok := newObj.(*v1alpha1.FirewallRule)
	if !ok {
		return nil, fmt.Errorf("expected a FirewallRule object for the newObj but got %T", newObj)
	}
	firewallrulelog.Info("Validation for FirewallRule upon update", "name", firewallrule.GetName())

	return v.validate(ctx, firewallrule)
}

// ValidateDelete implements webhook.CustomValidator so a webhook will be registered for the type FirewallRule.
func (v *FirewallRuleCustomValidator) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	firewallrule, ok := obj.(*v1alpha1.FirewallRule)
	if !ok {
		return nil, fmt.Errorf("expected a FirewallRule object but got %T", obj)
	}
	firewallrulelog.Info("Validation for FirewallRule upon deletion", "name", firewallrule.GetName())

	// TODO(user): fill in your validation logic upon object deletion.

	return nil, nil
}

// validate implements webhook.CustomValidator so a webhook will be registered for the type FirewallRule.
func (v *FirewallRuleCustomValidator) validate(ctx context.Context, firewallrule *v1alpha1.FirewallRule) (admission.Warnings, error) {
	var allErrs field.ErrorList

	path := field.NewPath("spec")
	nodename := ptr.Deref(firewallrule.Spec.NodeName, "")
	if nodename != "" {
		var firewallrules v1alpha1.FirewallRuleList
		if err := v.List(ctx, &firewallrules, client.MatchingFields{firewallRuleNodeNameKey: nodename}); err != nil {
			firewallrulelog.Error(err, "Unable to list FirewallRules")
			return nil, err
		}

		firewallrules.Items = slices.DeleteFunc(firewallrules.Items, func(fr v1alpha1.FirewallRule) bool {
			return fr.Name == firewallrule.Name
		})

		frSpec := provider.EncodeFirewallRuleSpec(firewallrule)
		frSpecs := provider.EncodeFirewallRuleSpecs(firewallrules.Items)

		if frSpec.Direction == provider.DirectionIngress &&
			provider.ContainsPermission(provider.GetIngressIPPermissions(frSpecs), frSpec.IPPermission) {
			allErrs = append(allErrs, field.Duplicate(path, firewallrule.Spec))
		} else if frSpec.Direction == provider.DirectionEgress &&
			provider.ContainsPermission(provider.GetEgressIPPermissions(frSpecs), frSpec.IPPermission) {
			allErrs = append(allErrs, field.Duplicate(path, firewallrule.Spec))
		}
	}

	if len(allErrs) > 0 {
		return nil, apierrors.NewInvalid(v1alpha1.GroupVersion.WithKind("FirewallRule").GroupKind(), firewallrule.Name, allErrs)
	}

	return nil, nil
}
