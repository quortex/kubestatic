// Package provider contains the cloud providers related interfaces and models.
package provider

import (
	"testing"

	"k8s.io/utils/ptr"
)

func Test_containsPermission(t *testing.T) {
	type args struct {
		slice []*IPPermission
		elem  *IPPermission
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "nil slice nil element should return false",
			args: args{
				slice: nil,
				elem:  nil,
			},
			want: false,
		},
		{
			name: "nil element should return false",
			args: args{
				slice: []*IPPermission{
					{
						FromPort: 0,
						IPRanges: nil,
						Protocol: "",
						ToPort:   ptr.To(int64(0)),
					},
				},
				elem: nil,
			},
			want: false,
		},
		{
			name: "non matching element should return false",
			args: args{
				slice: []*IPPermission{
					{
						FromPort: 1,
						IPRanges: []*IPRange{
							{
								CIDR:        "22.22.22.22",
								Description: "bar",
							},
						},
						Protocol: "UDP",
						ToPort:   ptr.To(int64(2)),
					},
					{
						FromPort: 1,
						IPRanges: []*IPRange{
							{
								CIDR:        "11.11.11.11",
								Description: "bar",
							},
						},
						Protocol: "UDP",
						ToPort:   ptr.To(int64(2)),
					},
					{
						FromPort: 1,
						IPRanges: []*IPRange{
							{
								CIDR:        "22.22.22.22",
								Description: "foo",
							},
						},
						Protocol: "UDP",
						ToPort:   ptr.To(int64(2)),
					},
				},
				elem: &IPPermission{
					FromPort: 1,
					IPRanges: []*IPRange{
						{
							CIDR:        "22.22.22.22",
							Description: "bar",
						},
					},
					Protocol: "TCP",
					ToPort:   ptr.To(int64(2)),
				},
			},
			want: false,
		},
		{
			name: "matching element should return true",
			args: args{
				slice: []*IPPermission{
					{
						FromPort: 1,
						IPRanges: []*IPRange{
							{
								CIDR:        "22.22.22.22",
								Description: "bar",
							},
						},
						Protocol: "TCP",
						ToPort:   ptr.To(int64(2)),
					},
				},
				elem: &IPPermission{
					FromPort: 1,
					IPRanges: []*IPRange{
						{
							CIDR:        "22.22.22.22",
							Description: "bar",
						},
					},
					Protocol: "TCP",
					ToPort:   ptr.To(int64(2)),
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ContainsPermission(tt.args.slice, tt.args.elem); got != tt.want {
				t.Errorf("containsPermission() = %v, want %v", got, tt.want)
			}
		})
	}
}
func Test_IsPermissionDuplicate(t *testing.T) {
	type args struct {
		slice []*IPPermission
		elem  *IPPermission
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "nil slice nil element should return false",
			args: args{
				slice: nil,
				elem:  nil,
			},
			want: false,
		},
		{
			name: "nil element should return false",
			args: args{
				slice: []*IPPermission{
					{
						FromPort: 0,
						IPRanges: nil,
						Protocol: "",
						ToPort:   ptr.To(int64(0)),
					},
				},
				elem: nil,
			},
			want: false,
		},
		{
			name: "non matching element should return false",
			args: args{
				slice: []*IPPermission{
					{
						FromPort: 1,
						IPRanges: []*IPRange{
							{
								CIDR:        "22.22.22.22",
								Description: "bar",
							},
						},
						Protocol: "UDP",
						ToPort:   ptr.To(int64(2)),
					},
					{
						FromPort: 1,
						IPRanges: []*IPRange{
							{
								CIDR:        "11.11.11.11",
								Description: "bar",
							},
						},
						Protocol: "UDP",
						ToPort:   ptr.To(int64(2)),
					},
					{
						FromPort: 1,
						IPRanges: []*IPRange{
							{
								CIDR:        "22.22.22.22",
								Description: "foo",
							},
						},
						Protocol: "UDP",
						ToPort:   ptr.To(int64(2)),
					},
				},
				elem: &IPPermission{
					FromPort: 1,
					IPRanges: []*IPRange{
						{
							CIDR:        "22.22.22.22",
							Description: "bar",
						},
					},
					Protocol: "TCP",
					ToPort:   ptr.To(int64(2)),
				},
			},
			want: false,
		},
		{
			name: "matching element should return false",
			args: args{
				slice: []*IPPermission{
					{
						FromPort: 1,
						IPRanges: []*IPRange{
							{
								CIDR:        "22.22.22.22",
								Description: "bar",
							},
						},
						Protocol: "TCP",
						ToPort:   ptr.To(int64(2)),
					},
				},
				elem: &IPPermission{
					FromPort: 1,
					IPRanges: []*IPRange{
						{
							CIDR:        "22.22.22.22",
							Description: "bar",
						},
					},
					Protocol: "TCP",
					ToPort:   ptr.To(int64(2)),
				},
			},
			want: false,
		},
		{
			name: "duplicate element should return true",
			args: args{
				slice: []*IPPermission{
					{
						FromPort: 1,
						IPRanges: []*IPRange{
							{
								CIDR:        "22.22.22.22",
								Description: "bar",
							},
						},
						Protocol: "TCP",
						ToPort:   ptr.To(int64(2)),
					},
					{
						FromPort: 1,
						IPRanges: []*IPRange{
							{
								CIDR:        "22.22.22.22",
								Description: "bar",
							},
						},
						Protocol: "TCP",
						ToPort:   ptr.To(int64(2)),
					},
				},
				elem: &IPPermission{
					FromPort: 1,
					IPRanges: []*IPRange{
						{
							CIDR:        "22.22.22.22",
							Description: "bar",
						},
					},
					Protocol: "TCP",
					ToPort:   ptr.To(int64(2)),
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsPermissionDuplicate(tt.args.slice, tt.args.elem); got != tt.want {
				t.Errorf("IsPermissionDuplicate() = %v, want %v", got, tt.want)
			}
		})
	}
}
