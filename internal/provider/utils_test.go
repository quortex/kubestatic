// Package provider contains the cloud providers related interfaces and models.
package provider

import (
	"reflect"
	"testing"

	"k8s.io/utils/ptr"
)

func Test_computePermissionRequests(t *testing.T) {
	type args struct {
		want []*IPPermission
		get  []*IPPermission
	}
	tests := []struct {
		name      string
		args      args
		wantToDel []IPPermission
		wantToAdd []IPPermission
	}{
		{
			name: "want no permission get no permission should return a no permission to add or del",
			args: args{
				want: nil,
				get:  nil,
			},
			wantToDel: nil,
			wantToAdd: nil,
		},
		{
			name: "want a permission get no permission should return a new permission to add",
			args: args{
				want: []*IPPermission{
					{
						FromPort: 1,
						IPRanges: []*IPRange{
							{
								CIDR:        "0.0.0.0/32",
								Description: "foo",
							},
						},
						Protocol: "UDP",
						ToPort:   ptr.To(int64(2)),
					},
				},
				get: nil,
			},
			wantToDel: nil,
			wantToAdd: []IPPermission{
				{
					IPRanges: []*IPRange{
						{
							CIDR:        "0.0.0.0/32",
							Description: "foo",
						},
					},
					FromPort: 1,
					Protocol: "UDP",
					ToPort:   ptr.To(int64(2)),
				},
			},
		},
		{
			name: "want no permission get a permission should return a new permission to del",
			args: args{
				want: nil,
				get: []*IPPermission{
					{
						FromPort: 1,
						IPRanges: []*IPRange{
							{
								CIDR:        "0.0.0.0/32",
								Description: "foo",
							},
						},
						Protocol: "UDP",
						ToPort:   ptr.To(int64(2)),
					},
				},
			},
			wantToDel: []IPPermission{
				{
					IPRanges: []*IPRange{
						{
							CIDR:        "0.0.0.0/32",
							Description: "foo",
						},
					},
					FromPort: 1,
					Protocol: "UDP",
					ToPort:   ptr.To(int64(2)),
				},
			},
			wantToAdd: nil,
		},
		{
			name: "want a permission get a different permission should return a permission to add and a permission to del",
			args: args{
				want: []*IPPermission{
					{
						FromPort: 2,
						IPRanges: []*IPRange{
							{
								CIDR:        "0.0.0.0/32",
								Description: "foo",
							},
						},
						Protocol: "TCP",
						ToPort:   ptr.To(int64(4)),
					},
				},
				get: []*IPPermission{
					{
						FromPort: 1,
						IPRanges: []*IPRange{
							{
								CIDR:        "0.0.0.0/32",
								Description: "foo",
							},
						},
						Protocol: "UDP",
						ToPort:   ptr.To(int64(2)),
					},
				},
			},
			wantToDel: []IPPermission{
				{
					IPRanges: []*IPRange{
						{
							CIDR:        "0.0.0.0/32",
							Description: "foo",
						},
					},
					FromPort: 1,
					Protocol: "UDP",
					ToPort:   ptr.To(int64(2)),
				},
			},
			wantToAdd: []IPPermission{
				{
					IPRanges: []*IPRange{
						{
							CIDR:        "0.0.0.0/32",
							Description: "foo",
						},
					},
					FromPort: 2,
					Protocol: "TCP",
					ToPort:   ptr.To(int64(4)),
				},
			},
		},
		{
			name: "want a complete permissions computing to return wanted adds and deletes requests",
			args: args{
				want: []*IPPermission{
					{
						FromPort: 2,
						IPRanges: []*IPRange{
							{
								CIDR: "1.1.1.1/32",
							},
							{
								CIDR: "2.2.2.2/32",
							},
						},
						Protocol: "TCP",
						ToPort:   ptr.To(int64(4)),
					},
				},
				get: []*IPPermission{
					{
						FromPort: 2,
						IPRanges: []*IPRange{
							{
								CIDR: "1.1.1.1/32",
							},
						},
						Protocol: "UDP",
						ToPort:   ptr.To(int64(4)),
					},
				},
			},
			wantToDel: []IPPermission{
				{
					IPRanges: []*IPRange{
						{
							CIDR: "1.1.1.1/32",
						},
					},
					FromPort: 2,
					Protocol: "UDP",
					ToPort:   ptr.To(int64(4)),
				},
			},
			wantToAdd: []IPPermission{
				{
					IPRanges: []*IPRange{
						{
							CIDR: "1.1.1.1/32",
						},
						{
							CIDR: "2.2.2.2/32",
						},
					},
					FromPort: 2,
					Protocol: "TCP",
					ToPort:   ptr.To(int64(4)),
				},
			},
		},
		{
			name: "want a complete permissions computing to return wanted adds and deletes requests",
			args: args{
				want: []*IPPermission{
					{
						FromPort: 5000,
						IPRanges: []*IPRange{
							{
								CIDR: "0.0.0.0/0",
							},
						},
						Protocol: "udp",
						ToPort:   ptr.To(int64(5000)),
					},
				},
				get: []*IPPermission{
					{
						FromPort: 0,
						IPRanges: []*IPRange{
							{
								CIDR: "0.0.0.0/0",
							},
						},
						Protocol: "-1",
						ToPort:   ptr.To(int64(0)),
					},
					{
						FromPort: 5000,
						IPRanges: []*IPRange{
							{
								CIDR: "0.0.0.0/0",
							},
						},
						Protocol: "udp",
						ToPort:   ptr.To(int64(5000)),
					},
				},
			},
			wantToDel: []IPPermission{
				{
					FromPort: 0,
					IPRanges: []*IPRange{
						{
							CIDR: "0.0.0.0/0",
						},
					},
					Protocol: "-1",
					ToPort:   ptr.To(int64(0)),
				},
			},
			wantToAdd: nil,
		},
		{
			name: "Remove to remove multiple permissions",
			args: args{
				want: []*IPPermission{
					{
						FromPort: 2,
						IPRanges: []*IPRange{
							{
								CIDR: "1.1.1.2/32",
							},
						},
						Protocol: "UDP",
						ToPort:   ptr.To(int64(4)),
					},
					{
						FromPort: 2,
						IPRanges: []*IPRange{
							{
								CIDR: "1.1.1.1/32",
							},
						},
						Protocol: "UDP",
						ToPort:   ptr.To(int64(4)),
					},
				},
				get: []*IPPermission{},
			},
			wantToDel: nil,
			wantToAdd: []IPPermission{
				{
					FromPort: 2,
					IPRanges: []*IPRange{
						{
							CIDR: "1.1.1.1/32",
						},
					},
					Protocol: "UDP",
					ToPort:   ptr.To(int64(4)),
				},
				{
					FromPort: 2,
					IPRanges: []*IPRange{
						{
							CIDR: "1.1.1.2/32",
						},
					},
					Protocol: "UDP",
					ToPort:   ptr.To(int64(4)),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotToDel, gotToAdd := computePermissionRequests(tt.args.want, tt.args.get)
			if !reflect.DeepEqual(gotToDel, tt.wantToDel) {
				t.Errorf("computePermissionRequests() gotToDel = %v, want %v", gotToDel, tt.wantToDel)
			}
			if !reflect.DeepEqual(gotToAdd, tt.wantToAdd) {
				t.Errorf("computePermissionRequests() gotToAdd = %v, want %v", gotToAdd, tt.wantToAdd)
			}
		})
	}
}

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
			if got := containsPermission(tt.args.slice, tt.args.elem); got != tt.want {
				t.Errorf("containsPermission() = %v, want %v", got, tt.want)
			}
		})
	}
}
