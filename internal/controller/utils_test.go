/*
Copyright 2021.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	"github.com/quortex/kubestatic/api/v1alpha1"
)

func Test_publicIPAddresses(t *testing.T) {
	type args struct {
		eips []v1alpha1.ExternalIP
	}
	tests := []struct {
		name    string
		args    args
		wantRes []string
	}{
		{
			name: "empty ExternalIPs should return empty public IP addresses",
			args: args{
				eips: nil,
			},
			wantRes: nil,
		},
		{
			name: "ExternalIPs with empty PublicIPAddress should return empty public IP addresses",
			args: args{
				eips: []v1alpha1.ExternalIP{
					{
						Status: v1alpha1.ExternalIPStatus{
							PublicIPAddress: nil,
						},
					},
				},
			},
			wantRes: nil,
		},
		{
			name: "ExternalIPs with empty PublicIPAddress should return empty public IP addresses",
			args: args{
				eips: []v1alpha1.ExternalIP{
					{
						Status: v1alpha1.ExternalIPStatus{
							PublicIPAddress: ptr.To("foo"),
						},
					},
					{
						Status: v1alpha1.ExternalIPStatus{
							PublicIPAddress: ptr.To("bar"),
						},
					},
				},
			},
			wantRes: []string{
				"foo",
				"bar",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotRes := publicIPAddresses(tt.args.eips); !reflect.DeepEqual(gotRes, tt.wantRes) {
				t.Errorf("publicIPAddresses() = %v, want %v", gotRes, tt.wantRes)
			}
		})
	}
}

func Test_countReferencedIP(t *testing.T) {
	type args struct {
		pods []corev1.Pod
		ip   string
	}
	tests := []struct {
		name      string
		args      args
		wantCount int
	}{
		{
			name: "empty pods should return zero",
			args: args{
				pods: nil,
				ip:   "foo",
			},
			wantCount: 0,
		},
		{
			name: "count referenced IP should work properly",
			args: args{
				pods: []corev1.Pod{
					{
						ObjectMeta: metav1.ObjectMeta{
							Labels: map[string]string{
								externalIPLabel: "foo",
							},
						},
					},
					{
						ObjectMeta: metav1.ObjectMeta{
							Labels: map[string]string{
								externalIPLabel: "foo",
							},
						},
					},
					{
						ObjectMeta: metav1.ObjectMeta{
							Labels: map[string]string{
								externalIPLabel: "bar",
							},
						},
					},
					{
						ObjectMeta: metav1.ObjectMeta{
							Labels: map[string]string{
								externalIPLabel: "foo",
							},
						},
					},
				},
				ip: "foo",
			},
			wantCount: 3,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotCount := countReferencedIP(tt.args.pods, tt.args.ip); gotCount != tt.wantCount {
				t.Errorf("countReferencedIP() = %v, want %v", gotCount, tt.wantCount)
			}
		})
	}
}

func Test_getMostReferencedIP(t *testing.T) {
	type args struct {
		pods []corev1.Pod
		eips []v1alpha1.ExternalIP
	}
	tests := []struct {
		name string
		args args
		want *v1alpha1.ExternalIP
	}{
		{
			name: "empty pods / empty ips should return nil",
			args: args{
				pods: nil,
				eips: nil,
			},
			want: nil,
		},
		{
			name: "get most referenced ip should work properly",
			args: args{
				pods: []corev1.Pod{
					{
						ObjectMeta: metav1.ObjectMeta{
							Labels: map[string]string{
								externalIPLabel: "foo",
							},
						},
					},
					{
						ObjectMeta: metav1.ObjectMeta{
							Labels: map[string]string{
								externalIPLabel: "foo",
							},
						},
					},
					{
						ObjectMeta: metav1.ObjectMeta{
							Labels: map[string]string{
								externalIPLabel: "bar",
							},
						},
					},
					{
						ObjectMeta: metav1.ObjectMeta{
							Labels: map[string]string{
								externalIPLabel: "foo",
							},
						},
					},
				},
				eips: []v1alpha1.ExternalIP{
					{
						Status: v1alpha1.ExternalIPStatus{
							PublicIPAddress: ptr.To("foo"),
						},
					},
					{
						Status: v1alpha1.ExternalIPStatus{
							PublicIPAddress: ptr.To("bar"),
						},
					},
				},
			},
			want: &v1alpha1.ExternalIP{
				Status: v1alpha1.ExternalIPStatus{
					PublicIPAddress: ptr.To("foo"),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getMostReferencedIP(tt.args.pods, tt.args.eips); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getMostReferencedIP() = %v, want %v", got, tt.want)
			}
		})
	}
}
