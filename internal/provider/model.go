// Package provider contains the cloud providers related interfaces and models.
package provider

import "github.com/quortex/kubestatic/api/v1alpha1"

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

	// A description for the security group rule that references this IPv4 address
	// range.
	//
	// AWS Constraints: Up to 255 characters in length. Allowed characters are a-z,
	// A-Z, 0-9, spaces, and ._-:/()#,@[]+=&;{}!$*
	Description string `json:"description"`
}

// IPPermission describes a set of permissions for a firewall rule.
type IPPermission struct {
	// The start of port range for the TCP and UDP protocols, or an ICMP/ICMPv6
	// type number.
	FromPort int64

	// The IP protocol name (tcp, udp, icmp, icmpv6) or number (see Protocol Numbers
	// (http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)).
	// Use -1 to specify all protocols.
	Protocol string

	// The IPv4 ranges.
	IPRanges []*IPRange

	// The end of port range for the TCP and UDP protocols, or an ICMP/ICMPv6 code.
	ToPort *int64
}

// FirewallRuleSpec describes the firewall rule configuration.
type FirewallRuleSpec struct {
	// The name of the firewall rule.
	Name string

	// A description for the firewall rule. This is informational only.
	Description string

	// The traffic direction. Ingress applies to incoming traffic. Egress applies to outbound traffic.
	Direction Direction

	// The permission associated with the firewall rule.
	IPPermission *IPPermission
}

// UpdateFirewallRuleRequest wraps parameters required to update a firewall rule group.
type UpdateFirewallRuleGroupRequest struct {
	// The ID of the firewall rule group.
	FirewallRuleGroupID string

	// The FirewallRules list.
	FirewallRules []FirewallRuleSpec
}

// EncodeFirewallRuleSpecs converts an api FirewallRule slice to a FirewallRuleSpec slice.
func EncodeFirewallRuleSpecs(data []v1alpha1.FirewallRule) []FirewallRuleSpec {
	if data == nil {
		return make([]FirewallRuleSpec, 0)
	}

	res := make([]FirewallRuleSpec, len(data))
	for i, e := range data {
		res[i] = EncodeFirewallRuleSpec(&e)
	}
	return res
}

// encodeFirewallRuleSpec converts an api FirewallRule to a FirewallRuleSpec.
func EncodeFirewallRuleSpec(data *v1alpha1.FirewallRule) FirewallRuleSpec {
	return FirewallRuleSpec{
		Name:        data.Name,
		Description: data.Spec.Description,
		Direction:   encodeDirection(data.Spec.Direction),
		IPPermission: &IPPermission{
			FromPort: data.Spec.FromPort,
			Protocol: data.Spec.Protocol,
			IPRanges: encodeIPRanges(data.Spec.IPRanges),
			ToPort:   data.Spec.ToPort,
		},
	}
}

// encodeIPRange converts an api IPRange to an IPRange.
func encodeIPRange(data *v1alpha1.IPRange) *IPRange {
	if data == nil {
		return nil
	}

	return &IPRange{
		CIDR:        data.CIDR,
		Description: data.Description,
	}
}

// encodeIPRange converts an api IPRange slice to an IPRange slice.
func encodeIPRanges(data []*v1alpha1.IPRange) []*IPRange {
	if data == nil {
		return make([]*IPRange, 0)
	}

	res := make([]*IPRange, len(data))
	for i, e := range data {
		res[i] = encodeIPRange(e)
	}
	return res
}

// encodeDirection converts an api Direction to a Direction.
func encodeDirection(data v1alpha1.Direction) Direction {
	switch data {
	case v1alpha1.DirectionEgress:
		return DirectionEgress
	case v1alpha1.DirectionIngress:
		return DirectionIngress
	}
	return Direction("")
}
