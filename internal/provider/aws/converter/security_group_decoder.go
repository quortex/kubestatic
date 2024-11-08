// Package converter provides conversion methods for ec2 models.
package converter

import (
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go/aws"

	"github.com/quortex/kubestatic/internal/provider"
)

// DecodeIpPermission converts an ec2 IpPermission to an IPPermission.
func DecodeIpPermission(data types.IpPermission) *provider.IPPermission {
	return &provider.IPPermission{
		FromPort: int64(aws.Int32Value(data.FromPort)),
		Protocol: aws.StringValue(data.IpProtocol),
		IPRanges: DecodeIpRanges(data.IpRanges),
		ToPort:   aws.Int64(int64(aws.Int32Value(data.ToPort))),
	}
}

// DecodeIpPermissions converts an ec2 IpPermission slice to an IPPermission slice.
func DecodeIpPermissions(data []types.IpPermission) []*provider.IPPermission {
	res := make([]*provider.IPPermission, len(data))
	for i, e := range data {
		res[i] = DecodeIpPermission(e)
	}
	return res
}

// DecodeIpRange converts an ec2 IpRange to an IPRange.
func DecodeIpRange(data types.IpRange) *provider.IPRange {
	return &provider.IPRange{
		CIDR:        aws.StringValue(data.CidrIp),
		Description: aws.StringValue(data.Description),
	}
}

// DecodeIpRanges converts an ec2 IpRange slice to an IPRange slice.
func DecodeIpRanges(data []types.IpRange) []*provider.IPRange {
	res := make([]*provider.IPRange, len(data))
	for i, e := range data {
		res[i] = DecodeIpRange(e)
	}
	return res
}
