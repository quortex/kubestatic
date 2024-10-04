// Package converter provides conversion methods for AWS models.
package converter

import (
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/quortex/kubestatic/internal/helper"
	"github.com/quortex/kubestatic/internal/provider"
)

func TestDecodeInstance(t *testing.T) {
	type args struct {
		data *ec2.Instance
	}
	tests := []struct {
		name string
		args args
		want *provider.Instance
	}{
		{
			name: "nil ec2 instance should return nil",
			args: args{
				data: nil,
			},
			want: nil,
		},
		{
			name: "empty ec2 instance should return empty instance",
			args: args{
				data: &ec2.Instance{},
			},
			want: &provider.Instance{},
		},
		{
			name: "complete ec2 instance should be decoded properly to instance",
			args: args{
				data: &ec2.Instance{
					InstanceId: aws.String("InstanceId"),
					VpcId:      aws.String("VpcId"),
					NetworkInterfaces: []*ec2.InstanceNetworkInterface{
						{
							NetworkInterfaceId: aws.String("FooNetworkInterfaceId"),
							Association: &ec2.InstanceNetworkInterfaceAssociation{
								PublicIp: aws.String("FooPublicIp"),
							},
							Attachment: &ec2.InstanceNetworkInterfaceAttachment{
								DeviceIndex: helper.Int64Pointer(1),
							},
						},
						{
							NetworkInterfaceId: aws.String("BarNetworkInterfaceId"),
							Association: &ec2.InstanceNetworkInterfaceAssociation{
								PublicIp: aws.String("BarPublicIp"),
							},
							Attachment: &ec2.InstanceNetworkInterfaceAttachment{
								DeviceIndex: helper.Int64Pointer(0),
							},
						},
					},
				},
			},
			want: &provider.Instance{
				InstanceID: "InstanceId",
				VpcID:      "VpcId",
				NetworkInterfaces: []*provider.NetworkInterface{
					{
						NetworkInterfaceID: "FooNetworkInterfaceId",
						PublicIP:           aws.String("FooPublicIp"),
						DeviceID:           helper.Int64Pointer(1),
					},
					{
						NetworkInterfaceID: "BarNetworkInterfaceId",
						PublicIP:           aws.String("BarPublicIp"),
						DeviceID:           helper.Int64Pointer(0),
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DecodeInstance(tt.args.data); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DecodeInstance() = %v, want %v", got, tt.want)
			}
		})
	}
}
