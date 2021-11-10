// Package provider contains the cloud providers related interfaces and models.
package provider

// Instance is a cloud provider compute instance.
type Instance struct {
	// The ID of the instance.
	InstanceID string

	// The ID of the VPC in which the instance is running.
	VpcID string

	// The network interfaces for the instance.
	NetworkInterfaces []*NetworkInterface
}

// NetworkInterface describes a network interface.
type NetworkInterface struct {
	// The ID of the network interface.
	NetworkInterfaceID string

	// The public IP address bound to the network interface.
	PublicIP *string
}

// Describes an external IP address.
type Address struct {
	// The ID of the address.
	AddressID string

	// The ID representing the association of the address with a network interface
	AssociationID *string

	// The address public IP.
	PublicIP string
}

// AssociateAddressRequest wraps parameters required to associate an Address to a Network interface.
type AssociateAddressRequest struct {
	// The ID of the address.
	AddressID string

	// The ID of the network interface that the address is associated with.
	NetworkInterfaceID string
}

// DisassociateAddressRequest wraps parameters required to disassociate an Address to a Network interface.
type DisassociateAddressRequest struct {
	// The association identifier.
	AssociationID string
}

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

// FirewallRule describes a set of permissions for a firewall.
type FirewallRule struct {
	// The ID of the firewall rule.
	FirewallRuleID string

	// The ID of the VPC.
	VpcID string

	FirewallRuleSpec
}

// FirewallRuleGroup describes a group of firewall rules.
type FirewallRuleGroup struct {
	// The name of the firewall rule group.
	Name string

	// A description for the firewall rule group. This is informational only.
	Description string

	// The FirewallRules list.
	FirewallRules []FirewallRuleSpec
}

// CreateFirewallRuleRequest wraps parameters required to create a firewall rule.
type CreateFirewallRuleRequest struct {
	FirewallRuleSpec
}

// CreateFirewallRuleGroupRequest wraps parameters required to create a firewall rule group.
type CreateFirewallRuleGroupRequest struct {
	// The name of the firewall rule group.
	Name string

	// A description for the firewall rule group. This is informational only.
	Description string

	// The FirewallRules list.
	FirewallRules []FirewallRuleSpec
}

// UpdateFirewallRuleRequest wraps parameters required to update a firewall rule.
type UpdateFirewallRuleRequest struct {
	FirewallRuleSpec

	// The ID of the firewall rule.
	FirewallRuleID string
}

// UpdateFirewallRuleRequest wraps parameters required to update a firewall rule group.
type UpdateFirewallRuleGroupRequest struct {
	// The ID of the firewall rule group.
	FirewallRuleGroupID string

	// The FirewallRules list.
	FirewallRules []FirewallRuleSpec
}

// AssociateFirewallRuleRequest wraps parameters required to associate a firewall rule to a Network interface.
type AssociateFirewallRuleRequest struct {
	// The ID of the firewall rule.
	FirewallRuleID string

	// The ID of the network interface that the firewall rule is associated with.
	NetworkInterfaceID string
}
