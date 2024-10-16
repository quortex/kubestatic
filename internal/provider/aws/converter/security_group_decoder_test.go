// Package converter provides conversion methods for ec2 models.
package converter

import (
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"

	"github.com/quortex/kubestatic/internal/provider"
)

func TestDecodeSecurityGroups(t *testing.T) {
	type args struct {
		data []*ec2.SecurityGroup
	}
	tests := []struct {
		name string
		args args
		want []*provider.FirewallRule
	}{
		{
			name: "various ec2 security groups should be decoded properly to firewall rules",
			args: args{
				data: []*ec2.SecurityGroup{
					nil,
					{},
					{
						Description: aws.String("FooDescription"),
						GroupId:     aws.String("FooGroupId"),
						GroupName:   aws.String("FooGroupName"),
						IpPermissions: []*ec2.IpPermission{
							{
								FromPort:   aws.Int64(2),
								IpProtocol: aws.String("tcp"),
								IpRanges: []*ec2.IpRange{
									{
										CidrIp:      aws.String("0.0.0.0/0"),
										Description: aws.String("FooCIDRDescription"),
									},
								},
								ToPort: aws.Int64(22),
							},
						},
						// If both Ingress and Egress permissions are set, Ingress has priority
						IpPermissionsEgress: []*ec2.IpPermission{
							{
								FromPort: aws.Int64(2),
							}},
						OwnerId: aws.String("FooOwnerId"),
						VpcId:   aws.String("FooVpcId"),
					},
					{
						Description: aws.String("BarDescription"),
						GroupId:     aws.String("BarGroupId"),
						GroupName:   aws.String("BarGroupName"),
						IpPermissionsEgress: []*ec2.IpPermission{
							{
								FromPort:   aws.Int64(4),
								IpProtocol: aws.String("tcp"),
								IpRanges: []*ec2.IpRange{
									{
										CidrIp:      aws.String("1.2.3.4/32"),
										Description: aws.String("BarCIDRDescription"),
									},
								},
								ToPort: aws.Int64(44),
							},
							// Multiple permissions, decode only the first.
							{
								FromPort: aws.Int64(2),
							},
						},
						OwnerId: aws.String("BarOwnerId"),
						VpcId:   aws.String("BarVpcId"),
					},
				},
			},
			want: []*provider.FirewallRule{
				nil,
				{},
				{
					FirewallRuleID: "FooGroupId",
					VpcID:          "FooVpcId",
					FirewallRuleSpec: provider.FirewallRuleSpec{
						Name:        "FooGroupName",
						Description: "FooDescription",
						Direction:   provider.DirectionIngress,
						IPPermission: &provider.IPPermission{
							FromPort: 2,
							Protocol: "tcp",
							IPRanges: []*provider.IPRange{
								{
									CIDR:        "0.0.0.0/0",
									Description: "FooCIDRDescription",
								},
							},
							ToPort: aws.Int64(22),
						},
					},
				},
				{
					FirewallRuleID: "BarGroupId",
					VpcID:          "BarVpcId",
					FirewallRuleSpec: provider.FirewallRuleSpec{
						Name:        "BarGroupName",
						Description: "BarDescription",
						Direction:   provider.DirectionEgress,
						IPPermission: &provider.IPPermission{
							FromPort: 4,
							Protocol: "tcp",
							IPRanges: []*provider.IPRange{
								{
									CIDR:        "1.2.3.4/32",
									Description: "BarCIDRDescription",
								},
							},
							ToPort: aws.Int64(44),
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DecodeSecurityGroups(tt.args.data); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DecodeSecurityGroups() = %v, want %v", got, tt.want)
			}
		})
	}
}
