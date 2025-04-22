// Package aws contains the provider implementation for AWS.
package aws

import (
	"context"
	"errors"
	"fmt"
	"path"
	"slices"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go/metrics/smithyotelmetrics"
	"github.com/go-logr/logr"
	"github.com/mitchellh/hashstructure/v2"
	"github.com/patrickmn/go-cache"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	kmetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"

	"github.com/quortex/kubestatic/api/v1alpha1"
	"github.com/quortex/kubestatic/internal/provider"
	"github.com/quortex/kubestatic/internal/provider/aws/converter"
)

// TagKey represents an AWS tag key.
type TagKey string

const (
	TagKeyDomain                = "kubestatic.quortex.io"            // Tag key domain
	TagKeyManaged        TagKey = TagKeyDomain + "/managed"          // Tag key for kubestatic managed resources
	TagKeyNodeName       TagKey = TagKeyDomain + "/node-name"        // Tag key for node name
	TagKeyInstanceID     TagKey = TagKeyDomain + "/instance-id"      // Tag key for instance ID
	TagKeyExternalIPName TagKey = TagKeyDomain + "/external-ip-name" // Tag key for external IP name
	TagKeyClusterID      TagKey = TagKeyDomain + "/cluster-id"       // Tag key for cluster ID
)

// FilterOption is a filter option for AWS API calls.
type FilterOption interface {
	Filter() types.Filter
}

// ManagedFilter is a filter option to get resources managed by kubestatic.
type ManagedFilter struct{}

func (f ManagedFilter) Filter() types.Filter {
	return types.Filter{
		Name:   aws.String(fmt.Sprintf("tag:%s", TagKeyManaged)),
		Values: []string{"true"},
	}
}

func Managed() ManagedFilter {
	return ManagedFilter{}
}

// VPCFilter is a filter option to get resources in a specific VPC.
type VPCFilter struct {
	VPCID string
}

func (f VPCFilter) Filter() types.Filter {
	return types.Filter{
		Name:   aws.String("vpc-id"),
		Values: []string{f.VPCID},
	}
}

func WithVPCID(vpcID string) VPCFilter {
	return VPCFilter{VPCID: vpcID}
}

// NodeNameFilter is a filter option to get resources associated with a specific node name.
type NodeNameFilter struct {
	NodeName string
}

func (f NodeNameFilter) Filter() types.Filter {
	return types.Filter{
		Name:   aws.String(fmt.Sprintf("tag:%s", TagKeyNodeName)),
		Values: []string{f.NodeName},
	}
}

func WithNodeName(nodeName string) NodeNameFilter {
	return NodeNameFilter{NodeName: nodeName}
}

// SecurityGroupIDFilter is a filter option to filter by security group ID.
type SecurityGroupIDFilter struct {
	SecurityGroupID string
}

func (f SecurityGroupIDFilter) Filter() types.Filter {
	return types.Filter{
		Name:   aws.String("group-id"),
		Values: []string{f.SecurityGroupID},
	}
}

func WithSecurityGroupID(securityGroupID string) SecurityGroupIDFilter {
	return SecurityGroupIDFilter{SecurityGroupID: securityGroupID}
}

// ExternalIPNameFilter is a filter option to filter by ExternalIP name.
type ExternalIPNameFilter struct {
	ExternalIPName string
}

func (f ExternalIPNameFilter) Filter() types.Filter {
	return types.Filter{
		Name:   aws.String(fmt.Sprintf("tag:%s", TagKeyExternalIPName)),
		Values: []string{f.ExternalIPName},
	}
}

func WithExternalIPName(externalIPName string) ExternalIPNameFilter {
	return ExternalIPNameFilter{ExternalIPName: externalIPName}
}

// AddressIDFilter is a filter option to filter by address ID.
type AddressIDFilter struct {
	AddressID string
}

func (f AddressIDFilter) Filter() types.Filter {
	return types.Filter{
		Name:   aws.String("allocation-id"),
		Values: []string{f.AddressID},
	}
}

func WithAddressID(addressID string) AddressIDFilter {
	return AddressIDFilter{AddressID: addressID}
}

// ClusterIDFilter is a filter option to filter by environment ID.
type ClusterIDFilter struct {
	ClusterID string
}

func (f ClusterIDFilter) Filter() types.Filter {
	return types.Filter{
		Name:   aws.String(fmt.Sprintf("tag:%s", TagKeyClusterID)),
		Values: []string{f.ClusterID},
	}
}

func WithClusterID(clusterID string) ClusterIDFilter {
	return ClusterIDFilter{ClusterID: clusterID}
}

// awsProvider is an AWS provider implementation for the provider.Provider interface
type awsProvider struct {
	clusterID string
	ec2       *ec2.Client
	// These Mutexes ensure that when a cache miss occurs, only one controller makes
	// the AWS API call while others wait for the result, preventing duplicate
	// requests for the same data.
	instancesMutex         sync.Mutex
	instancesCache         *cache.Cache
	securityGroupsMutex    sync.Mutex
	securityGroupsCache    *cache.Cache
	networkInterfacesMutex sync.Mutex
	networkInterfacesCache *cache.Cache
	addressesMutex         sync.Mutex
	addressesCache         *cache.Cache
}

// NewProvider instantiate a Provider implementation for AWS
func NewProvider(defaultTTL, defaultCleanupInterval time.Duration, clusterID string) (provider.Provider, error) {
	// Load the Shared AWS Configuration (~/.aws/config)
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return nil, err
	}

	meterProvider, err := NewMeterProvider()
	if err != nil {
		return nil, err
	}

	return &awsProvider{
		clusterID: clusterID,
		ec2: ec2.NewFromConfig(cfg, func(o *ec2.Options) {
			// https://github.com/aws/aws-sdk-go-v2/discussions/2810
			o.MeterProvider = smithyotelmetrics.Adapt(meterProvider)
		}),
		instancesCache:         cache.New(defaultTTL, defaultCleanupInterval),
		securityGroupsCache:    cache.New(defaultTTL, defaultCleanupInterval),
		networkInterfacesCache: cache.New(defaultTTL, defaultCleanupInterval),
		addressesCache:         cache.New(defaultTTL, defaultCleanupInterval),
	}, nil
}

// Standalone generic function for fetching AWS resources
func getResource[T any](
	ctx context.Context,
	cache *cache.Cache,
	mu *sync.Mutex,
	cacheKey string,
	apiCall func(context.Context, []types.Filter) (T, error),
	opts ...FilterOption,
) (T, error) {
	var zero T // Default zero value for the generic type

	// We lock here so that multiple callers do not result in cache misses and multiple
	// calls to AWS API when we could have just made one call.
	mu.Lock()
	defer mu.Unlock()

	// Convert filter options to AWS filters
	filters := make([]types.Filter, len(opts))
	for _, opt := range opts {
		filters = append(filters, opt.Filter())
	}

	if cacheKey == "" {
		// Hash the filters
		hash, err := hashstructure.Hash(filters, hashstructure.FormatV2, &hashstructure.HashOptions{SlicesAsSets: true})
		if err != nil {
			return zero, converter.DecodeEC2Error("failed to hash filters", err)
		}

		cacheKey = fmt.Sprint(hash)
	}

	// Check cache
	if cached, ok := cache.Get(cacheKey); ok {
		return cached.(T), nil
	}

	// Call the provided AWS API function
	resource, err := apiCall(ctx, filters)
	if err != nil {
		return zero, err
	}

	// Store in cache
	cache.SetDefault(cacheKey, resource)
	return resource, nil
}

// Wrapper function for fetching Addresses
func (p *awsProvider) getAddress(ctx context.Context, opts ...FilterOption) (*types.Address, error) {
	apiCall := func(ctx context.Context, filters []types.Filter) (*types.Address, error) {
		res, err := p.ec2.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{Filters: filters})
		if err != nil {
			return nil, converter.DecodeEC2Error("failed to list addresses", err)
		}
		if len(res.Addresses) == 0 {
			return nil, &provider.Error{
				Code: provider.NotFoundError,
				Msg:  "failed to get address: address not found",
			}
		}
		return &res.Addresses[0], nil
	}
	return getResource(ctx, p.addressesCache, &p.addressesMutex, "", apiCall, opts...)
}

// Wrapper function for fetching securityGroups
func (p *awsProvider) getSecurityGroup(ctx context.Context, opts ...FilterOption) (*types.SecurityGroup, error) {
	apiCall := func(ctx context.Context, filters []types.Filter) (*types.SecurityGroup, error) {
		res, err := p.ec2.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{Filters: filters})
		if err != nil {
			return nil, converter.DecodeEC2Error("failed to list security groups", err)
		}
		if len(res.SecurityGroups) == 0 {
			return nil, &provider.Error{
				Code: provider.NotFoundError,
				Msg:  "failed to get security group: security group not found",
			}
		}
		return &res.SecurityGroups[0], nil
	}
	return getResource(ctx, p.securityGroupsCache, &p.securityGroupsMutex, "", apiCall, opts...)
}

// GetInstanceID returns the instance ID from a node
func (p *awsProvider) GetInstanceID(node corev1.Node) string {
	return path.Base(node.Spec.ProviderID)
}

func (p *awsProvider) getInstance(ctx context.Context, instanceID string) (*types.Instance, error) {
	apiCall := func(ctx context.Context, _ []types.Filter) (*types.Instance, error) {
		res, err := p.ec2.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
			InstanceIds: []string{instanceID},
		})
		if err != nil {
			return nil, converter.DecodeEC2Error("failed to get instance", err)
		}
		if len(res.Reservations) == 0 || len(res.Reservations[0].Instances) == 0 {
			return nil, &provider.Error{
				Code: provider.NotFoundError,
				Msg:  fmt.Sprintf("failed to get instance: instance with instance-id %s not found", instanceID),
			}
		}
		return &res.Reservations[0].Instances[0], nil
	}

	return getResource(ctx, p.instancesCache, &p.instancesMutex, instanceID, apiCall)
}

func (p *awsProvider) getNetworkInterfaces(ctx context.Context, securityGroupID string) ([]types.NetworkInterface, error) {
	apiCall := func(ctx context.Context, _ []types.Filter) ([]types.NetworkInterface, error) {
		res, err := p.ec2.DescribeNetworkInterfaces(ctx, &ec2.DescribeNetworkInterfacesInput{
			Filters: []types.Filter{
				{
					Name:   aws.String("group-id"),
					Values: []string{securityGroupID},
				},
			},
		})
		if err != nil {
			return nil, converter.DecodeEC2Error("failed to list network interfaces", err)
		}
		return res.NetworkInterfaces, nil
	}

	return getResource(ctx, p.networkInterfacesCache, &p.networkInterfacesMutex, securityGroupID, apiCall)
}

func eniWithPublicIP(instance *types.Instance) (*types.InstanceNetworkInterface, error) {
	idx := slices.IndexFunc(instance.NetworkInterfaces, func(ni types.InstanceNetworkInterface) bool {
		return ni.Association != nil && ni.Association.PublicIp != nil
	})
	if idx == -1 {
		return nil, fmt.Errorf("no network interface with public IP found for instance %s", aws.ToString(instance.InstanceId))
	}
	return &instance.NetworkInterfaces[idx], nil
}

func (p *awsProvider) createSecurityGroup(ctx context.Context, vpcID, nodeName, instanceID string) (string, error) {
	p.securityGroupsMutex.Lock()
	defer p.securityGroupsMutex.Unlock()

	res, err := p.ec2.CreateSecurityGroup(ctx, &ec2.CreateSecurityGroupInput{
		GroupName:   aws.String(fmt.Sprintf("kubestatic-%s", rand.String(10))),
		Description: aws.String(fmt.Sprintf("Kubestatic managed group for instance %s", instanceID)),
		VpcId:       aws.String(vpcID),
		TagSpecifications: []types.TagSpecification{
			{
				ResourceType: types.ResourceTypeSecurityGroup,
				Tags: []types.Tag{
					{
						Key:   aws.String(string(TagKeyManaged)),
						Value: aws.String("true"),
					},
					{
						Key:   aws.String(string(TagKeyNodeName)),
						Value: aws.String(nodeName),
					},
					{
						Key:   aws.String(string(TagKeyInstanceID)),
						Value: aws.String(instanceID),
					},
					{
						Key:   aws.String(string(TagKeyClusterID)),
						Value: aws.String(p.clusterID),
					},
				},
			},
		},
	})
	if err != nil {
		return "", converter.DecodeEC2Error("failed to create security group", err)
	}

	p.securityGroupsCache.Flush()

	return aws.ToString(res.GroupId), nil
}

func (p *awsProvider) deleteSecurityGroup(ctx context.Context, securityGroupID string) error {
	p.securityGroupsMutex.Lock()
	defer p.securityGroupsMutex.Unlock()

	_, err := p.ec2.DeleteSecurityGroup(ctx, &ec2.DeleteSecurityGroupInput{
		GroupId: aws.String(securityGroupID),
	})
	if err != nil {
		return converter.DecodeEC2Error("failed to delete security group", err)
	}

	p.securityGroupsCache.Flush()

	return nil
}

func (p *awsProvider) authorizeSecurityGroupIngress(ctx context.Context, log logr.Logger, firewallRuleID string, req provider.IPPermission) error {
	p.securityGroupsMutex.Lock()
	defer p.securityGroupsMutex.Unlock()

	_, err := p.ec2.AuthorizeSecurityGroupIngress(ctx, &ec2.AuthorizeSecurityGroupIngressInput{
		GroupId: &firewallRuleID,
		IpPermissions: []types.IpPermission{
			converter.EncodeIPPermission(req),
		},
	})
	if err != nil {
		return converter.DecodeEC2Error("failed to authorize security group ingress permission", err)
	}
	log.Info("Security group ingress permission authorized", "firewallRuleID", firewallRuleID, "permission", req)

	p.securityGroupsCache.Flush()

	return nil
}

func (p *awsProvider) revokeSecurityGroupIngress(ctx context.Context, log logr.Logger, firewallRuleID string, req provider.IPPermission) error {
	p.securityGroupsMutex.Lock()
	defer p.securityGroupsMutex.Unlock()

	_, err := p.ec2.RevokeSecurityGroupIngress(ctx, &ec2.RevokeSecurityGroupIngressInput{
		GroupId: aws.String(firewallRuleID),
		IpPermissions: []types.IpPermission{
			converter.EncodeIPPermission(req),
		},
	})
	if err != nil {
		return converter.DecodeEC2Error("failed to revoke security group ingress permission", err)
	}
	log.Info("Security group ingress permission revoked", "firewallRuleID", firewallRuleID, "permission", req)

	p.securityGroupsCache.Flush()

	return nil
}

func (p *awsProvider) authorizeSecurityGroupEgress(ctx context.Context, log logr.Logger, firewallRuleID string, req provider.IPPermission) error {
	p.securityGroupsMutex.Lock()
	defer p.securityGroupsMutex.Unlock()

	_, err := p.ec2.AuthorizeSecurityGroupEgress(ctx, &ec2.AuthorizeSecurityGroupEgressInput{
		GroupId: aws.String(firewallRuleID),
		IpPermissions: []types.IpPermission{
			converter.EncodeIPPermission(req),
		},
	})
	if err != nil {
		return converter.DecodeEC2Error("failed to authorize security group egress permission", err)
	}
	log.Info("Security group egress permission authorized", "firewallRuleID", firewallRuleID, "permission", req)

	p.securityGroupsCache.Flush()

	return nil
}

func (p *awsProvider) revokeSecurityGroupEgress(ctx context.Context, log logr.Logger, firewallRuleID string, req provider.IPPermission) error {
	p.securityGroupsMutex.Lock()
	defer p.securityGroupsMutex.Unlock()

	_, err := p.ec2.RevokeSecurityGroupEgress(ctx, &ec2.RevokeSecurityGroupEgressInput{
		GroupId: aws.String(firewallRuleID),
		IpPermissions: []types.IpPermission{
			converter.EncodeIPPermission(req),
		},
	})
	if err != nil {
		return converter.DecodeEC2Error("failed to revoke security group egress permission", err)
	}
	log.Info("Security group egress permission revoked", "firewallRuleID", firewallRuleID, "permission", req)

	p.securityGroupsCache.Flush()

	return nil
}

// revokeUselessPermission revokes ingress and egress permissions from a security group that are
// not present in the provided firewall rules specifications.
//
// Parameters:
//   - ctx: The context for controlling cancellation and deadlines.
//   - log: The logger for logging information and errors.
//   - securityGroupID: The ID of the security group from which permissions will be revoked.
//   - frSpecs: A list of firewall rule specifications to compare against existing permissions.
//   - ingress: A list of existing ingress permissions in the security group.
//   - egress: A list of existing egress permissions in the security group.
//
// Returns:
//   - error: An error if any permission revocation fails, otherwise nil.
func (p *awsProvider) revokeUselessPermission(
	ctx context.Context,
	log logr.Logger,
	securityGroupID string,
	frSpecs []provider.FirewallRuleSpec,
	ingress []*provider.IPPermission,
	egress []*provider.IPPermission,
) error {
	// Rules in the security group, that are not in the firewall rules list are considered useless.
	for _, e := range ingress {
		if !provider.ContainsPermission(provider.GetIngressIPPermissions(frSpecs), e) {
			if err := p.revokeSecurityGroupIngress(ctx, log, securityGroupID, *e); err != nil {
				return err
			}
		}
	}
	for _, e := range egress {
		if !provider.ContainsPermission(provider.GetEgressIPPermissions(frSpecs), e) {
			if err := p.revokeSecurityGroupEgress(ctx, log, securityGroupID, *e); err != nil {
				return err
			}
		}
	}

	return nil
}

func (p *awsProvider) createAddress(ctx context.Context, externalIPName, instanceID string) (string, error) {
	p.addressesMutex.Lock()
	defer p.addressesMutex.Unlock()

	res, err := p.ec2.AllocateAddress(ctx, &ec2.AllocateAddressInput{
		Domain: types.DomainTypeVpc,
		TagSpecifications: []types.TagSpecification{
			{
				ResourceType: types.ResourceTypeElasticIp,
				Tags: []types.Tag{
					{
						Key:   aws.String(string(TagKeyManaged)),
						Value: aws.String("true"),
					},
					{
						Key:   aws.String(string(TagKeyExternalIPName)),
						Value: aws.String(externalIPName),
					},
					{
						Key:   aws.String(string(TagKeyInstanceID)),
						Value: aws.String(instanceID),
					},
					{
						Key:   aws.String(string(TagKeyClusterID)),
						Value: aws.String(p.clusterID),
					},
				},
			},
		},
	})
	if err != nil {
		return "", converter.DecodeEC2Error("failed to create address", err)
	}

	p.addressesCache.Flush()

	return aws.ToString(res.AllocationId), nil
}

func (p *awsProvider) associateAddress(ctx context.Context, addressID, networkInterfaceID string) error {
	p.addressesMutex.Lock()
	defer p.addressesMutex.Unlock()

	_, err := p.ec2.AssociateAddress(ctx, &ec2.AssociateAddressInput{
		AllocationId:       &addressID,
		NetworkInterfaceId: &networkInterfaceID,
	})
	if err != nil {
		return converter.DecodeEC2Error("failed to associate address", err)
	}

	p.addressesCache.Flush()

	return nil
}

func (p *awsProvider) disassociateAddress(ctx context.Context, associationID string) error {
	p.addressesMutex.Lock()
	defer p.addressesMutex.Unlock()

	_, err := p.ec2.DisassociateAddress(ctx, &ec2.DisassociateAddressInput{
		AssociationId: &associationID,
	})
	if err != nil {
		return converter.DecodeEC2Error("failed to disassociate address", err)
	}

	p.addressesCache.Flush()

	return nil
}

func (p *awsProvider) deleteAddress(ctx context.Context, addressID string) error {
	p.addressesMutex.Lock()
	defer p.addressesMutex.Unlock()

	_, err := p.ec2.ReleaseAddress(ctx, &ec2.ReleaseAddressInput{
		AllocationId: &addressID,
	})
	if err != nil {
		return converter.DecodeEC2Error("failed to delete address", err)
	}

	p.addressesCache.Flush()

	return nil
}

// ReconcileFirewallRule ensures that the firewall rule for a given node and instance in AWS.
// It performs the following steps:
//  1. Retrieves the instance information using the provided instance ID.
//  2. Retrieves or creates a security group associated with the instance.
//  3. Associates the security group with the network interface that has a public IP address.
//  4. Disassociates the security group from other network interfaces.
//  5. Applies ingress and egress permissions to the security group based on the provided firewall rules.
//
// Parameters:
//   - ctx: The context for the operation.
//   - log: Logger for logging errors and information.
//   - nodeName: The name of the node.
//   - instanceID: The ID of the instance.
//   - firewallRule: The firewall rule to be applied.
//   - firewallRules: The list of firewall rules on the node.
//
// Returns:
//   - v1alpha1.FirewallRuleStatus: The status of the firewall rule reconciliation.
//   - error: An error if the reconciliation fails.
func (p *awsProvider) ReconcileFirewallRule(
	ctx context.Context,
	log logr.Logger,
	nodeName, instanceID string,
	firewallRule *v1alpha1.FirewallRule,
	firewallrules []v1alpha1.FirewallRule,
) (v1alpha1.FirewallRuleStatus, error) {
	status := v1alpha1.FirewallRuleStatus{
		State:      v1alpha1.FirewallRuleStatePending,
		Conditions: slices.Clone(firewallRule.Status.Conditions),
	}

	// Get the instance
	instance, err := p.getInstance(ctx, instanceID)
	if err != nil {
		return status, fmt.Errorf("failed to get instance: %w", err)
	}

	// Get the security group associated with the instance
	securityGroup, err := p.getSecurityGroup(
		ctx,
		Managed(),
		WithClusterID(p.clusterID),
		WithVPCID(aws.ToString(instance.VpcId)),
		WithNodeName(nodeName),
	)
	if err != nil && err.(*provider.Error).Code != provider.NotFoundError {
		meta.SetStatusCondition(&status.Conditions, kmetav1.Condition{
			Type:               v1alpha1.FirewallRuleConditionTypeSecurityGroupCreated,
			Status:             kmetav1.ConditionUnknown,
			ObservedGeneration: firewallRule.Generation,
			Reason:             v1alpha1.FirewallRuleConditionReasonProviderError,
			Message:            fmt.Sprintf("Fail to get security group from AWS : %s", err),
		})
		return status, fmt.Errorf("failed to get security group: %w", err)
	}

	if securityGroup == nil {
		if !firewallRule.DeletionTimestamp.IsZero() {
			// Object is in process of being deleted – likely going to disappear
			log.Info("FirewallRule found with deletion timestamp and no security group created. Ignoring since object must be deleted")
			return status, nil
		}

		securityGroupID, err := p.createSecurityGroup(ctx, aws.ToString(instance.VpcId), nodeName, instanceID)
		if err != nil {
			meta.SetStatusCondition(&status.Conditions, kmetav1.Condition{
				Type:               v1alpha1.FirewallRuleConditionTypeSecurityGroupCreated,
				Status:             kmetav1.ConditionFalse,
				ObservedGeneration: firewallRule.Generation,
				Reason:             v1alpha1.FirewallRuleConditionReasonProviderError,
				Message:            fmt.Sprintf("Failed to create security group: %s", err),
			})
			return status, fmt.Errorf("failed to create security group: %w", err)
		}

		log.Info("Security group created", "securityGroupID", securityGroupID)

		securityGroup, err = p.getSecurityGroup(
			ctx,
			Managed(),
			WithClusterID(p.clusterID),
			WithVPCID(aws.ToString(instance.VpcId)),
			WithNodeName(nodeName),
			WithSecurityGroupID(securityGroupID),
		)
		if err != nil {
			meta.SetStatusCondition(&status.Conditions, kmetav1.Condition{
				Type:               v1alpha1.FirewallRuleConditionTypeNetworkInterfaceAssociated,
				Status:             kmetav1.ConditionUnknown,
				ObservedGeneration: firewallRule.Generation,
				Reason:             v1alpha1.FirewallRuleConditionReasonProviderError,
				Message:            fmt.Sprintf("Failed to get security group: %s", err),
			})
			return status, fmt.Errorf("failed to get security group: %w", err)
		}
	}

	meta.SetStatusCondition(&status.Conditions, kmetav1.Condition{
		Type:               v1alpha1.FirewallRuleConditionTypeSecurityGroupCreated,
		Status:             kmetav1.ConditionTrue,
		ObservedGeneration: firewallRule.Generation,
		Reason:             v1alpha1.FirewallRuleConditionReasonSecurityGroupCreated,
		Message:            fmt.Sprintf("Security group created with nodename %s in %s", nodeName, aws.ToString(instance.VpcId)),
	})

	securityGroupID := aws.ToString(securityGroup.GroupId)
	status.FirewallRuleID = securityGroup.GroupId

	// Get the first network interface with a public IP address
	networkInterface, err := eniWithPublicIP(instance)
	if err != nil {
		meta.SetStatusCondition(&status.Conditions, kmetav1.Condition{
			Type:               v1alpha1.FirewallRuleConditionTypeNetworkInterfaceAssociated,
			Status:             kmetav1.ConditionUnknown,
			ObservedGeneration: firewallRule.Generation,
			Reason:             v1alpha1.FirewallRuleConditionReasonProviderError,
			Message:            fmt.Sprintf("Failed to get network interface with public IP: %s", err),
		})
		return status, fmt.Errorf("failed to get network interface with public IP: %w", err)
	}

	// Get all network interfaces associated with the security group
	networkInterfaces, err := p.getNetworkInterfaces(ctx, securityGroupID)
	if err != nil {
		meta.SetStatusCondition(&status.Conditions, kmetav1.Condition{
			Type:               v1alpha1.FirewallRuleConditionTypeNetworkInterfaceAssociated,
			Status:             kmetav1.ConditionUnknown,
			ObservedGeneration: firewallRule.Generation,
			Reason:             v1alpha1.FirewallRuleConditionReasonProviderError,
			Message:            fmt.Sprintf("Failed to list network interfaces: %s", err),
		})
		return status, fmt.Errorf("failed to list network interfaces: %w", err)
	}

	isAssociated := false
	for _, ni := range networkInterfaces {
		if aws.ToString(ni.NetworkInterfaceId) == aws.ToString(networkInterface.NetworkInterfaceId) {
			isAssociated = true
			continue
		}

		// Disassociate the security group from other network interfaces
		groups := []string{}
		for _, group := range ni.Groups {
			if aws.ToString(group.GroupId) != securityGroupID {
				groups = append(groups, aws.ToString(group.GroupId))
			}
		}

		p.networkInterfacesMutex.Lock()
		_, err = p.ec2.ModifyNetworkInterfaceAttribute(ctx, &ec2.ModifyNetworkInterfaceAttributeInput{
			NetworkInterfaceId: ni.NetworkInterfaceId,
			Groups:             groups,
		})
		if err != nil {
			meta.SetStatusCondition(&status.Conditions, kmetav1.Condition{
				Type:               v1alpha1.FirewallRuleConditionTypeNetworkInterfaceAssociated,
				Status:             kmetav1.ConditionFalse,
				ObservedGeneration: firewallRule.Generation,
				Reason:             v1alpha1.FirewallRuleConditionReasonProviderError,
				Message:            fmt.Sprintf("Failed to modify network interface attribute: %s", err),
			})
			return status, fmt.Errorf("failed to modify network interface attribute: %w", err)
		}
		log.Info("Security group disassociated from network interface", "securityGroupID", securityGroupID, "networkInterfaceID", ni.NetworkInterfaceId)

		p.networkInterfacesCache.Delete(securityGroupID)
		p.networkInterfacesMutex.Unlock()
	}

	if !isAssociated {
		// Associate the security group with the network interface
		// Disassociate the security group from other network interfaces
		groups := []string{}
		for _, group := range networkInterface.Groups {
			if aws.ToString(group.GroupId) != securityGroupID {
				groups = append(groups, aws.ToString(group.GroupId))
			}
		}
		groups = append(groups, securityGroupID)
		p.networkInterfacesMutex.Lock()
		_, err = p.ec2.ModifyNetworkInterfaceAttribute(ctx, &ec2.ModifyNetworkInterfaceAttributeInput{
			NetworkInterfaceId: networkInterface.NetworkInterfaceId,
			Groups:             groups,
		})
		if err != nil {
			meta.SetStatusCondition(&status.Conditions, kmetav1.Condition{
				Type:               v1alpha1.FirewallRuleConditionTypeNetworkInterfaceAssociated,
				Status:             kmetav1.ConditionFalse,
				ObservedGeneration: firewallRule.Generation,
				Reason:             v1alpha1.FirewallRuleConditionReasonProviderError,
				Message: fmt.Sprintf(
					"Security group not associated with network interface %s: %s",
					aws.ToString(networkInterface.NetworkInterfaceId),
					err,
				),
			})
			return status, fmt.Errorf("failed to modify network interface attribute: %w", err)
		}
		log.Info("Security group associated with network interface",
			"securityGroupID", securityGroupID,
			"networkInterfaceID", networkInterface.NetworkInterfaceId,
		)

		p.networkInterfacesCache.Delete(securityGroupID)
		p.networkInterfacesMutex.Unlock()
	}

	meta.SetStatusCondition(&status.Conditions, kmetav1.Condition{
		Type:               v1alpha1.FirewallRuleConditionTypeNetworkInterfaceAssociated,
		Status:             kmetav1.ConditionTrue,
		ObservedGeneration: firewallRule.Generation,
		Reason:             v1alpha1.FirewallRuleConditionReasonNetworkInterfaceAssociated,
		Message:            fmt.Sprintf("Security group associated with network interface %s", aws.ToString(networkInterface.NetworkInterfaceId)),
	})

	status.InstanceID = &instanceID
	status.NetworkInterfaceID = networkInterface.NetworkInterfaceId

	frSpec := provider.EncodeFirewallRuleSpec(firewallRule)
	frSpecs := provider.EncodeFirewallRuleSpecs(firewallrules)

	if err := p.revokeUselessPermission(
		ctx,
		log,
		securityGroupID,
		frSpecs,
		converter.DecodeIpPermissions(securityGroup.IpPermissions),
		converter.DecodeIpPermissions(securityGroup.IpPermissionsEgress),
	); err != nil {
		return status, fmt.Errorf("failed to revoke useless permissions: %w", err)
	}

	if !firewallRule.DeletionTimestamp.IsZero() {
		if frSpec.Direction == provider.DirectionIngress &&
			provider.ContainsPermission(converter.DecodeIpPermissions(securityGroup.IpPermissions), frSpec.IPPermission) {
			if len(securityGroup.IpPermissions) == 1 && len(securityGroup.IpPermissionsEgress) == 0 {
				// If the security group has only one ingress rule and no egress rule, delete the security group
				if err := p.ReconcileFirewallRulesDeletion(ctx, log, nodeName); err != nil {
					return status, fmt.Errorf("failed to reconcile FirewallRule deletion: %w", err)
				}
			} else {
				// Revoke Ingress permissions reconciliation
				if err := p.revokeSecurityGroupIngress(ctx, log, securityGroupID, *frSpec.IPPermission); err != nil {
					return status, fmt.Errorf("failed to delete security group ingress permission: %w", err)
				}
			}
		}

		if frSpec.Direction == provider.DirectionEgress &&
			provider.ContainsPermission(converter.DecodeIpPermissions(securityGroup.IpPermissionsEgress), frSpec.IPPermission) {
			if len(securityGroup.IpPermissionsEgress) == 1 && len(securityGroup.IpPermissions) == 0 {
				// If the security group has only one egress rule and no ingress rule, delete the security group
				if err := p.ReconcileFirewallRulesDeletion(ctx, log, nodeName); err != nil {
					return status, fmt.Errorf("failed to reconcile FirewallRule deletion: %w", err)
				}
			} else {
				// Revoke Egress permissions reconciliation
				if err := p.revokeSecurityGroupEgress(ctx, log, securityGroupID, *frSpec.IPPermission); err != nil {
					return status, fmt.Errorf("failed to delete security group egress permission: %w", err)
				}
			}
		}

		return status, nil
	}

	// Apply Ingress permissions reconciliation
	if frSpec.Direction == provider.DirectionIngress {
		// Apply Ingress permissions reconciliation
		if err := provider.ReconcilePermissions(
			ctx,
			log,
			securityGroupID,
			p.authorizeSecurityGroupIngress,
			frSpec.IPPermission,
			converter.DecodeIpPermissions(securityGroup.IpPermissions),
		); err != nil {
			if provider.IsErrRulesPerSecurityGroupLimitExceeded(err) {
				meta.SetStatusCondition(&status.Conditions, kmetav1.Condition{
					Type:               v1alpha1.FirewallRuleConditionTypeSecurityGroupRuleAuthorized,
					Status:             kmetav1.ConditionFalse,
					ObservedGeneration: firewallRule.Generation,
					Reason:             v1alpha1.FirewallRuleConditionReasonProviderError,
					Message:            "Could not created ingress rule: the maximum number of rules per security group has been reached",
				})
			} else {
				meta.SetStatusCondition(&status.Conditions, kmetav1.Condition{
					Type:               v1alpha1.FirewallRuleConditionTypeSecurityGroupRuleAuthorized,
					Status:             kmetav1.ConditionFalse,
					ObservedGeneration: firewallRule.Generation,
					Reason:             v1alpha1.FirewallRuleConditionReasonProviderError,
					Message:            fmt.Sprintf("Failed to reconcile permissions : %s", err),
				})
			}
			return status, fmt.Errorf("failed to apply security group ingress permissions: %w", err)
		}
	}

	if frSpec.Direction == provider.DirectionEgress {
		// Apply Egress permissions reconciliation
		if err := provider.ReconcilePermissions(
			ctx,
			log,
			securityGroupID,
			p.authorizeSecurityGroupEgress,
			frSpec.IPPermission,
			converter.DecodeIpPermissions(securityGroup.IpPermissionsEgress),
		); err != nil {
			if provider.IsErrRulesPerSecurityGroupLimitExceeded(err) {
				meta.SetStatusCondition(&status.Conditions, kmetav1.Condition{
					Type:               v1alpha1.FirewallRuleConditionTypeSecurityGroupRuleAuthorized,
					Status:             kmetav1.ConditionFalse,
					ObservedGeneration: firewallRule.Generation,
					Reason:             v1alpha1.FirewallRuleConditionReasonProviderError,
					Message:            "Could not created egress rule: the maximum number of rules per security group has been reached",
				})
			} else {
				meta.SetStatusCondition(&status.Conditions, kmetav1.Condition{
					Type:               v1alpha1.FirewallRuleConditionTypeSecurityGroupRuleAuthorized,
					Status:             kmetav1.ConditionFalse,
					ObservedGeneration: firewallRule.Generation,
					Reason:             v1alpha1.FirewallRuleConditionReasonProviderError,
					Message:            fmt.Sprintf("Failed to reconcile permissions : %s", err),
				})
			}
			return status, fmt.Errorf("failed to apply security group egress permissions: %w", err)
		}
	}

	status.State = v1alpha1.FirewallRuleStateApplied
	meta.SetStatusCondition(&status.Conditions, kmetav1.Condition{
		Type:               v1alpha1.FirewallRuleConditionTypeSecurityGroupRuleAuthorized,
		Status:             kmetav1.ConditionTrue,
		ObservedGeneration: firewallRule.Generation,
		Reason:             v1alpha1.FirewallRuleConditionReasonSecurityGroupRuleAuthorized,
		Message:            "The rule has been successfully authorized in the security group",
	})

	return status, nil
}

// ReconcileFirewallRulesDeletion reconciles the deletion of firewall rules for a given node.
// It retrieves the security group associated with the instance, disassociates it from all network interfaces,
// and then deletes the security group.
//
// Parameters:
//   - ctx: The context for the operation.
//   - log: Logger for logging errors and information.
//   - nodeName: The name of the node for which to reconcile firewall rules deletion.
//
// Returns:
//   - error: An error if the reconciliation fails, otherwise nil.
func (p *awsProvider) ReconcileFirewallRulesDeletion(
	ctx context.Context,
	log logr.Logger,
	nodeName string,
) error {
	// Get the security group associated with the instance
	securityGroup, err := p.getSecurityGroup(ctx, Managed(), WithClusterID(p.clusterID), WithNodeName(nodeName))
	if err != nil {
		// The security group does not exist, end of reconciliation
		if err.(*provider.Error).Code == provider.NotFoundError {
			return nil
		}
		return fmt.Errorf("failed to get security group: %w", err)
	}
	securityGroupID := aws.ToString(securityGroup.GroupId)

	// Get all network interfaces associated with the security group
	networkInterfaces, err := p.getNetworkInterfaces(ctx, securityGroupID)
	if err != nil {
		return fmt.Errorf("failed to list network interfaces: %w", err)
	}

	for _, ni := range networkInterfaces {
		// Disassociate the security group from all network interfaces
		groups := []string{}
		for _, group := range ni.Groups {
			if aws.ToString(group.GroupId) != securityGroupID {
				groups = append(groups, aws.ToString(group.GroupId))
			}
		}

		p.networkInterfacesMutex.Lock()
		_, err = p.ec2.ModifyNetworkInterfaceAttribute(ctx, &ec2.ModifyNetworkInterfaceAttributeInput{
			NetworkInterfaceId: ni.NetworkInterfaceId,
			Groups:             groups,
		})
		p.networkInterfacesCache.Delete(securityGroupID)
		p.networkInterfacesMutex.Unlock()

		if err != nil {
			return fmt.Errorf("failed to modify network interface attribute: %w", err)
		}
		log.Info("Security group disassociated from network interface", "securityGroupID", securityGroupID, "networkInterfaceID", ni.NetworkInterfaceId)
	}

	if err := p.deleteSecurityGroup(ctx, securityGroupID); err != nil {
		return fmt.Errorf("failed to delete security group: %w", err)
	}
	log.Info("Security group deleted", "securityGroupID", securityGroupID)

	return nil
}

// ReconcileExternalIP ensures that the external IP is correctly associated with the given instance.
// If the external IP does not exist, it will be created. If the instance ID is empty, the external IP
// will be disassociated from any network interface it is currently associated with.
//
// Parameters:
//   - ctx: The context for the operation.
//   - log: Logger for logging errors and information.
//   - instanceID: The ID of the instance to associate the external IP with. If empty, the external IP
//     will be disassociated from any network interface.
//   - externalIP: The external IP object to reconcile.
//
// Returns:
//   - v1alpha1.ExternalIPStatus: The status of the external IP after reconciliation.
//   - error: Any error encountered during the reconciliation process.
func (p *awsProvider) ReconcileExternalIP(
	ctx context.Context,
	log logr.Logger,
	instanceID string,
	externalIP *v1alpha1.ExternalIP,
) (v1alpha1.ExternalIPStatus, error) {
	status := v1alpha1.ExternalIPStatus{
		State:      v1alpha1.ExternalIPStatePending,
		Conditions: slices.Clone(externalIP.Status.Conditions),
	}

	// Get the address associated with the instance
	address, err := p.getAddress(ctx, Managed(), WithClusterID(p.clusterID), WithExternalIPName(externalIP.Name))
	if err != nil && err.(*provider.Error).Code != provider.NotFoundError {
		meta.SetStatusCondition(&status.Conditions, kmetav1.Condition{
			Type:               v1alpha1.ExternalIPConditionReasonIPCreated,
			Status:             kmetav1.ConditionUnknown,
			ObservedGeneration: externalIP.Generation,
			Reason:             v1alpha1.FirewallRuleConditionReasonProviderError,
			Message:            fmt.Sprintf("Failed to get address: %s", err),
		})
		return status, fmt.Errorf("failed to get address: %w", err)
	}

	if address == nil {
		addressID, err := p.createAddress(ctx, externalIP.Name, instanceID)
		if err != nil {
			if provider.IsErrAddressLimitExceeded(err) {
				meta.SetStatusCondition(&status.Conditions, kmetav1.Condition{
					Type:               v1alpha1.ExternalIPConditionReasonIPCreated,
					Status:             kmetav1.ConditionFalse,
					ObservedGeneration: externalIP.Generation,
					Reason:             v1alpha1.ExternalIPConditionReasonProviderError,
					Message:            "Could not create address: The maximum number of addresses has been reached",
				})
			} else {
				meta.SetStatusCondition(&status.Conditions, kmetav1.Condition{
					Type:               v1alpha1.ExternalIPConditionReasonIPCreated,
					Status:             kmetav1.ConditionFalse,
					ObservedGeneration: externalIP.Generation,
					Reason:             v1alpha1.ExternalIPConditionReasonProviderError,
					Message:            fmt.Sprintf("Failed to create address: %s", err),
				})
			}

			return status, fmt.Errorf("failed to create address: %w", err)
		}
		log.Info("Address created", "addressID", addressID)

		address, err = p.getAddress(ctx, Managed(), WithClusterID(p.clusterID), WithExternalIPName(externalIP.Name), WithAddressID(addressID))
		if err != nil {
			meta.SetStatusCondition(&status.Conditions, kmetav1.Condition{
				Type:               v1alpha1.ExternalIPConditionReasonIPCreated,
				Status:             kmetav1.ConditionTrue,
				ObservedGeneration: externalIP.Generation,
				Reason:             v1alpha1.ExternalIPConditionReasonProviderError,
				Message:            fmt.Sprintf("Failed to get address: %s", err),
			})
			return status, fmt.Errorf("failed to get address: %w", err)
		}
	}
	status.State = v1alpha1.ExternalIPStateReserved
	status.AddressID = address.AllocationId
	status.PublicIPAddress = address.PublicIp

	meta.SetStatusCondition(&status.Conditions, kmetav1.Condition{
		Type:               v1alpha1.ExternalIPConditionReasonIPCreated,
		Status:             kmetav1.ConditionTrue,
		ObservedGeneration: externalIP.Generation,
		Reason:             v1alpha1.ExternalIPConditionReasonIPCreated,
		Message:            "The IP has been successfully created",
	})

	if instanceID == "" {
		meta.SetStatusCondition(&status.Conditions, kmetav1.Condition{
			Type:               v1alpha1.ExternalIPConditionTypeNetworkInterfaceAssociated,
			Status:             kmetav1.ConditionFalse,
			ObservedGeneration: externalIP.Generation,
			Reason:             v1alpha1.ExternalIPConditionReasonProviderError,
			Message:            "Address has no instanceID",
		})

		if address.AssociationId == nil {
			return status, nil
		}

		// Disassociate the address from the current network interface
		if err := p.disassociateAddress(ctx, *address.AssociationId); err != nil {
			return status, fmt.Errorf("failed to disassociate address: %w", err)
		}
		log.Info("Address disassociated", "addressID", address.AllocationId, "associationID", *address.AssociationId)

		status.InstanceID = nil
		status.State = v1alpha1.ExternalIPStateReserved
		return status, nil
	}

	// Get the instance
	instance, err := p.getInstance(ctx, instanceID)
	if err != nil {
		return status, fmt.Errorf("failed to get instance: %w", err)
	}

	// Get the first network interface with a public IP address
	networkInterface, err := eniWithPublicIP(instance)
	if err != nil {
		meta.SetStatusCondition(&status.Conditions, kmetav1.Condition{
			Type:               v1alpha1.ExternalIPConditionTypeNetworkInterfaceAssociated,
			Status:             kmetav1.ConditionUnknown,
			ObservedGeneration: externalIP.Generation,
			Reason:             v1alpha1.ExternalIPConditionReasonProviderError,
			Message:            fmt.Sprintf("Failed to get network interface with public IP: %s", err),
		})
		return status, fmt.Errorf("failed to get network interface with public IP: %w", err)
	}

	if address.NetworkInterfaceId != nil {
		// Address is already associated with the instance
		if *address.NetworkInterfaceId == *networkInterface.NetworkInterfaceId {
			status.State = v1alpha1.ExternalIPStateAssociated

			meta.SetStatusCondition(&status.Conditions, kmetav1.Condition{
				Type:               v1alpha1.ExternalIPConditionTypeNetworkInterfaceAssociated,
				Status:             kmetav1.ConditionTrue,
				ObservedGeneration: externalIP.Generation,
				Reason:             v1alpha1.ExternalIPConditionReasonNetworkInterfaceAssociated,
				Message: fmt.Sprintf("Address %s associated with network interface %s",
					aws.ToString(address.AllocationId), aws.ToString(networkInterface.NetworkInterfaceId)),
			})
			return status, nil
		}

		// Disassociate the address from the current network interface
		if err := p.disassociateAddress(ctx, *address.AssociationId); err != nil {
			meta.SetStatusCondition(&status.Conditions, kmetav1.Condition{
				Type:               v1alpha1.ExternalIPConditionTypeNetworkInterfaceAssociated,
				Status:             kmetav1.ConditionFalse,
				ObservedGeneration: externalIP.Generation,
				Reason:             v1alpha1.ExternalIPConditionReasonProviderError,
				Message: fmt.Sprintf("Failed to disassociate address %s with %s",
					aws.ToString(address.AllocationId), aws.ToString(address.AssociationId)),
			})
			return status, fmt.Errorf("failed to disassociate address: %w", err)
		}
		log.Info("Address disassociated", "addressID", address.AllocationId, "associationID", *address.AssociationId)

		status.InstanceID = nil
		status.State = v1alpha1.ExternalIPStateReserved
	}

	// Associate the address with the network interface
	if err := p.associateAddress(ctx, aws.ToString(address.AllocationId), *networkInterface.NetworkInterfaceId); err != nil {
		meta.SetStatusCondition(&status.Conditions, kmetav1.Condition{
			Type:               v1alpha1.ExternalIPConditionTypeNetworkInterfaceAssociated,
			Status:             kmetav1.ConditionFalse,
			ObservedGeneration: externalIP.Generation,
			Reason:             v1alpha1.ExternalIPConditionReasonProviderError,
			Message:            fmt.Sprintf("Failed to associate address: %s", err),
		})

		return status, fmt.Errorf("failed to associate address: %w", err)
	}
	log.Info("Address associated", "addressID", address.AllocationId, "networkInterfaceID", *networkInterface.NetworkInterfaceId)

	status.InstanceID = &instanceID
	status.State = v1alpha1.ExternalIPStateAssociated

	meta.SetStatusCondition(&status.Conditions, kmetav1.Condition{
		Type:               v1alpha1.ExternalIPConditionTypeNetworkInterfaceAssociated,
		Status:             kmetav1.ConditionTrue,
		ObservedGeneration: externalIP.Generation,
		Reason:             v1alpha1.ExternalIPConditionReasonNetworkInterfaceAssociated,
		Message: fmt.Sprintf("Address %s associated with network interface %s",
			aws.ToString(address.AllocationId), aws.ToString(networkInterface.NetworkInterfaceId)),
	})

	return status, nil
}

// ReconcileExternalIPDeletion handles the deletion of an external IP address in AWS.
// If the address is associated with a network interface, it disassociates the address
// before deleting it.
//
// Parameters:
//   - ctx: The context for managing request deadlines and cancellation signals.
//   - log: Logger for logging errors and information.
//   - externalIP: The ExternalIP resource to be deleted.
//
// Returns:
//   - error: An error if the reconciliation fails, otherwise nil.
func (p *awsProvider) ReconcileExternalIPDeletion(
	ctx context.Context,
	log logr.Logger,
	externalIP *v1alpha1.ExternalIP,
) error {
	// Get the address associated with the instance
	address, err := p.getAddress(ctx, Managed(), WithClusterID(p.clusterID), WithExternalIPName(externalIP.Name))
	if err != nil {
		var providerErr *provider.Error
		// The address does not exist, end of reconciliation
		if errors.As(err, &providerErr) && providerErr.Code == provider.NotFoundError {
			return nil
		}
		return fmt.Errorf("failed to get address: %w", err)
	}

	if address.AssociationId != nil {
		// Disassociate the address from the network interface
		if err := p.disassociateAddress(ctx, *address.AssociationId); err != nil {
			return fmt.Errorf("failed to disassociate address: %w", err)
		}
		log.Info("Address disassociated", "addressID", address.AllocationId, "associationID", *address.AssociationId)
	}

	if err := p.deleteAddress(ctx, aws.ToString(address.AllocationId)); err != nil {
		return fmt.Errorf("failed to delete address: %w", err)
	}
	log.Info("Address deleted", "addressID", address.AllocationId)

	return nil
}
