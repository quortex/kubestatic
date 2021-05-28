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
