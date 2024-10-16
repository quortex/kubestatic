// Package converter provides conversion methods for AWS models.
package converter

import (
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"

	"github.com/quortex/kubestatic/internal/provider"
)

func TestDecodeAddress(t *testing.T) {
	type args struct {
		data *ec2.Address
	}
	tests := []struct {
		name string
		args args
		want *provider.Address
	}{
		{
			name: "nil ec2 address should return nil",
			args: args{
				data: nil,
			},
			want: nil,
		},
		{
			name: "empty ec2 address should return empty address",
			args: args{
				data: &ec2.Address{},
			},
			want: &provider.Address{},
		},
		{
			name: "complete ec2 address should be decoded properly to address",
			args: args{
				data: &ec2.Address{
					AllocationId:  aws.String("AllocationId"),
					AssociationId: aws.String("AssociationId"),
					PublicIp:      aws.String("PublicIp"),
				},
			},
			want: &provider.Address{
				AddressID:     "AllocationId",
				AssociationID: aws.String("AssociationId"),
				PublicIP:      "PublicIp",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DecodeAddress(tt.args.data); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DecodeAddress() = %v, want %v", got, tt.want)
			}
		})
	}
}
