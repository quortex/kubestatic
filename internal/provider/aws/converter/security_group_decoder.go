// Package converter provides conversion methods for ec2 models.
package converter

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/quortex/kubestatic/internal/provider"
)

// DecodeSecurityGroup converts an ec2 SecurityGroup to a Firewall.
func DecodeSecurityGroup(data *ec2.SecurityGroup) *provider.FirewallRule {
	if data == nil {
		return nil
	}

	var permission *provider.IPPermission
	var direction provider.Direction
	if len(data.IpPermissions) > 0 {
		permission = DecodeIpPermission(data.IpPermissions[0])
		direction = provider.DirectionIngress
	} else if len(data.IpPermissionsEgress) > 0 {
		permission = DecodeIpPermission(data.IpPermissionsEgress[0])
		direction = provider.DirectionEgress
	}

	return &provider.FirewallRule{
		FirewallRuleID: aws.StringValue(data.GroupId),
		VpcID:          aws.StringValue(data.VpcId),
		FirewallRuleSpec: provider.FirewallRuleSpec{
			Name:         aws.StringValue(data.GroupName),
			Description:  aws.StringValue(data.Description),
			Direction:    direction,
			IPPermission: permission,
		},
	}
}

// DecodeSecurityGroups converts an ec2 SecurityGroup slice to a Firewall slice.
func DecodeSecurityGroups(data []*ec2.SecurityGroup) []*provider.FirewallRule {
	if data == nil {
		return make([]*provider.FirewallRule, 0)
	}

	res := make([]*provider.FirewallRule, len(data))
	for i, e := range data {
		res[i] = DecodeSecurityGroup(e)
	}
	return res
}

// DecodeIpPermission converts an ec2 IpPermission to an IPPermission.
func DecodeIpPermission(data *ec2.IpPermission) *provider.IPPermission {
	if data == nil {
		return nil
	}

	return &provider.IPPermission{
		FromPort: aws.Int64Value(data.FromPort),
		Protocol: aws.StringValue(data.IpProtocol),
		IPRanges: DecodeIpRanges(data.IpRanges),
		ToPort:   data.ToPort,
	}
}

// DecodeIpPermissions converts an ec2 IpPermission slice to an IPPermission slice.
func DecodeIpPermissions(data []*ec2.IpPermission) []*provider.IPPermission {
	if data == nil {
		return make([]*provider.IPPermission, 0)
	}

	res := make([]*provider.IPPermission, len(data))
	for i, e := range data {
		res[i] = DecodeIpPermission(e)
	}
	return res
}

// DecodeIpRange converts an ec2 IpRange to an IPRange.
func DecodeIpRange(data *ec2.IpRange) *provider.IPRange {
	if data == nil {
		return nil
	}

	return &provider.IPRange{
		CIDR:        aws.StringValue(data.CidrIp),
		Description: aws.StringValue(data.Description),
	}
}

// DecodeIpRanges converts an ec2 IpRange slice to an IPRange slice.
func DecodeIpRanges(data []*ec2.IpRange) []*provider.IPRange {
	if data == nil {
		return make([]*provider.IPRange, 0)
	}

	res := make([]*provider.IPRange, len(data))
	for i, e := range data {
		res[i] = DecodeIpRange(e)
	}
	return res
}
