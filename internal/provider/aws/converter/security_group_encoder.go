// Package converter provides conversion methods for ec2 models.
package converter

import (
	"slices"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"k8s.io/utils/ptr"

	"github.com/quortex/kubestatic/internal/provider"
)

// EncodeIPPermission converts an IPPermission to an ec2 IpPermission.
func EncodeIPPermission(req provider.IPPermission) *ec2.IpPermission {
	res := &ec2.IpPermission{
		IpProtocol: aws.String(req.Protocol),
		IpRanges:   EncodeIpRanges(req.IPRanges),
	}

	// fromport / toport must be specified for the tcp / udp protocol even if they are zero.
	// On the contrary, they must be omitted for the other protocols if they are zero.
	if slices.Contains([]string{"udp", "tcp", "UDP", "TCP"}, req.Protocol) {
		res.FromPort = aws.Int64(req.FromPort)
		res.ToPort = req.ToPort
		if res.ToPort == nil {
			res.ToPort = aws.Int64(req.FromPort)
		}
	} else {
		if req.FromPort != 0 {
			res.FromPort = ptr.To(req.FromPort)
		}
		res.ToPort = req.ToPort
	}

	return res
}

// EncodeIpRange converts an IPRange to an ec2 IpRange.
func EncodeIpRange(data *provider.IPRange) *ec2.IpRange {
	if data == nil {
		return nil
	}

	res := &ec2.IpRange{
		CidrIp: aws.String(data.CIDR),
	}
	if data.Description != "" {
		res.Description = ptr.To(data.Description)
	}
	return res
}

// EncodeIpRanges converts an IPRange slice to an ec2 IpRange slice.
func EncodeIpRanges(data []*provider.IPRange) []*ec2.IpRange {
	if data == nil {
		return make([]*ec2.IpRange, 0)
	}

	res := make([]*ec2.IpRange, len(data))
	for i, e := range data {
		res[i] = EncodeIpRange(e)
	}
	return res
}
