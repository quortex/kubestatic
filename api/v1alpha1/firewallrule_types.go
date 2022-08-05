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

// Direction describes the traffic direction.
// Ingress applies to incoming traffic. Egress applies to outbound traffic.
type Direction string

// All defined Direction
const (
	DirectionIngress Direction = "Ingress"
	DirectionEgress  Direction = "Egress"
)

// IPRange Describes an IPv4 range.
type IPRange struct {
	// The IPv4 CIDR range. You can either specify a CIDR range or a source security
	// group, not both. To specify a single IPv4 address, use the /32 prefix length.
	CIDR string `json:"cidr"`

	// A description for the rule that references this IPv4 address
	// range.
	Description string `json:"description"`
}

// FirewallRuleSpec defines the desired state of FirewallRule
type FirewallRuleSpec struct {
	// NodeName is the node's instance on which the firewall rule must be attached
	// +optional
	NodeName *string `json:"nodeName,omitempty"`

	// A description for the firewall rule. This is informational only.
	Description string `json:"description"`

	// The traffic direction. Ingress applies to incoming traffic. Egress applies to outbound traffic.
	//+kubebuilder:validation:Enum:={"Ingress","Egress"}
	Direction Direction `json:"direction"`

	// The start of port range for the TCP and UDP protocols, or an ICMP/ICMPv6
	// type number.
	FromPort int64 `json:"fromPort"`

	// The IP protocol name (tcp, udp, icmp, icmpv6) or number (see Protocol Numbers
	// (http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)).
	// Use -1 to specify all protocols.
	Protocol string `json:"protocol"`

	// The IPv4 ranges.
	IPRanges []*IPRange `json:"ipRanges,omitempty"`

	// The end of port range for the TCP and UDP protocols, or an ICMP/ICMPv6 code.
	ToPort *int64 `json:"toPort,omitempty"`

	// Whether to disable reconciliation of this resource for development purpose
	//+kubebuilder:validation:Optional
	//+kubebuilder:default:=false
	DisableReconciliation bool `json:"disableReconciliation"`
}

// FirewallRuleState describes the FirewallRule state.
type FirewallRuleState string

// All defined FirewallRuleStates
const (
	FirewallRuleStateNone       FirewallRuleState = ""
	FirewallRuleStateReserved   FirewallRuleState = "Reserved"
	FirewallRuleStateAssociated FirewallRuleState = "Associated"
)

// FirewallRuleStatus defines the observed state of FirewallRule
type FirewallRuleStatus struct {
	// The current state of the FirewallRule
	State FirewallRuleState `json:"state,omitempty"`

	// The latest FirewallRule specification applied, used to make API requests to cloud providers only if the resource has been changed to avoid throttling issues.
	LastApplied *string `json:"lastApplied,omitempty"`

	// The firewall rule dientifier
	FirewallRuleID *string `json:"firewallRuleID,omitempty"`

	// The instance identifier
	InstanceID *string `json:"instanceID,omitempty"`

	// The network interface identifier
	NetworkInterfaceID *string `json:"networkInterfaceID,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:resource:scope=Cluster
//+kubebuilder:printcolumn:name="Direction",type=string,JSONPath=`.spec.direction`
//+kubebuilder:printcolumn:name="State",type=string,JSONPath=`.status.state`
//+kubebuilder:printcolumn:name="Node",type=string,JSONPath=`.spec.nodeName`

// FirewallRule is the Schema for the firewallrules API
type FirewallRule struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   FirewallRuleSpec   `json:"spec,omitempty"`
	Status FirewallRuleStatus `json:"status,omitempty"`
}

// IsReserved returns if firewallRule is reserved
func (f *FirewallRule) IsReserved() bool {
	return f.Status.State == FirewallRuleStateReserved
}

// IsAssociated returns if firewallRule is associated
func (f *FirewallRule) IsAssociated() bool {
	return f.Status.State == FirewallRuleStateAssociated
}

//+kubebuilder:object:root=true

// FirewallRuleList contains a list of FirewallRule
type FirewallRuleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FirewallRule `json:"items"`
}

func init() {
	SchemeBuilder.Register(&FirewallRule{}, &FirewallRuleList{})
}

// FilterFirewallRules filter FirewallRules depending on the given filter function.
// Filter function must return true to keep element, false to filter it.
func FilterFirewallRules(frs []FirewallRule, filterFunc func(FirewallRule) bool) []FirewallRule {
	res := []FirewallRule{}
	for _, e := range frs {
		if filterFunc(e) {
			res = append(res, e)
		}
	}
	return res
}
