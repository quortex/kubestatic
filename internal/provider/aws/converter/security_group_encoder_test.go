// Package converter provides conversion methods for ec2 models.
package converter

import (
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"

	"github.com/quortex/kubestatic/internal/provider"
)

func TestEncodeIPPermission(t *testing.T) {
	type args struct {
		req provider.IPPermission
	}
	tests := []struct {
		name string
		args args
		want *ec2.IpPermission
	}{
		{
			name: "empty IPPermissions should be decoded to empty ec2 IPPermission",
			args: args{
				req: provider.IPPermission{
					FromPort: 0,
					Protocol: "",
					IPRanges: nil,
					ToPort:   nil,
				},
			},
			want: &ec2.IpPermission{
				IpProtocol: aws.String(""),
				IpRanges:   []*ec2.IpRange{},
			},
		},
		{
			name: "complete IPPermissions should be decoded to complete ec2 IPPermission",
			args: args{
				req: provider.IPPermission{
					FromPort: 22,
					Protocol: "udp",
					IPRanges: []*provider.IPRange{
						{
							CIDR:        "FooCIDR",
							Description: "FooDescription",
						},
						{
							CIDR:        "BarCIDR",
							Description: "BarDescription",
						},
					},
					ToPort: aws.Int64(44),
				},
			},
			want: &ec2.IpPermission{
				FromPort:   aws.Int64(22),
				IpProtocol: aws.String("udp"),
				IpRanges: []*ec2.IpRange{
					{
						CidrIp:      aws.String("FooCIDR"),
						Description: aws.String("FooDescription"),
					},
					{
						CidrIp:      aws.String("BarCIDR"),
						Description: aws.String("BarDescription"),
					},
				},
				ToPort: aws.Int64(44),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := EncodeIPPermission(tt.args.req); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("EncodeIPPermission() = %v, want %v", got, tt.want)
			}
		})
	}
}
