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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ExternalIPSpec defines the desired state of ExternalIP
type ExternalIPSpec struct {
	// NodeName is the node's instance on which the address must be attached
	// +optional
	NodeName string `json:"nodeName,omitempty"`

	// PreventDeallocation tells if EIP should be deallocated on ExternalIP deletion
	//+kubebuilder:validation:Optional
	//+kubebuilder:default:=false
	PreventEIPDeallocation bool `json:"preventEIPDeallocation,omitempty"`
}

// ExternalIPState describes the ExternalIP state.
type ExternalIPState string

// All defined ExternalIPStates
const (
	ExternalIPStateNone       ExternalIPState = ""
	ExternalIPStateReserved   ExternalIPState = "Reserved"
	ExternalIPStateAssociated ExternalIPState = "Associated"
	// ExternalIPAutoAssignLabel is the key for auto externalIP assignment label
	ExternalIPAutoAssignLabel = "kubestatic.quortex.io/externalip-auto-assign"
	// ExternalIPLabel is the key for auto externalIP label (the externalIP a pod should have)
	ExternalIPLabel = "kubestatic.quortex.io/externalip"
	// ExternalIPNodeNameField is the nodeName field in ExternalIP resource
	ExternalIPNodeNameField = ".spec.nodeName"
)

// ExternalIPStatus defines the observed state of ExternalIP
type ExternalIPStatus struct {
	// The current state of the ExternalIP
	State ExternalIPState `json:"state,omitempty"`

	// The address identifier
	AddressID *string `json:"addressID,omitempty"`

	// The address public IP
	PublicIPAddress *string `json:"publicIPAddress,omitempty"`

	// The instance identifier
	InstanceID *string `json:"instanceID,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:resource:scope=Cluster
//+kubebuilder:printcolumn:name="State",type=string,JSONPath=`.status.state`
//+kubebuilder:printcolumn:name="Public IP",type=string,JSONPath=`.status.publicIPAddress`
//+kubebuilder:printcolumn:name="Node",type=string,JSONPath=`.spec.nodeName`

// ExternalIP is the Schema for the externalips API
type ExternalIP struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ExternalIPSpec   `json:"spec,omitempty"`
	Status ExternalIPStatus `json:"status,omitempty"`
}

// IsReserved returns if externalIP is reserved
func (e *ExternalIP) IsReserved() bool {
	return e.Status.State == ExternalIPStateReserved
}

// IsAssociated returns if externalIP is associated
func (e *ExternalIP) IsAssociated() bool {
	return e.Status.State == ExternalIPStateAssociated
}

// ShouldDisassociate returns true if EIP should disassociate from node, based on label
func (e *ExternalIP) ShouldDisassociate() bool {
	return e.Labels[ExternalIPAutoAssignLabel] != "true"
}

//+kubebuilder:object:root=true

// ExternalIPList contains a list of ExternalIP
type ExternalIPList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ExternalIP `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ExternalIP{}, &ExternalIPList{})
}
