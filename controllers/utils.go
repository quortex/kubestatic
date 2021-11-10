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

package controllers

import (
	"math/rand"
	"time"

	"github.com/quortex/kubestatic/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
)

// publicIPAddresses returns public IP addresses of the given ExternalIPs
func publicIPAddresses(eips []v1alpha1.ExternalIP) (res []string) {
	for _, e := range eips {
		if e.Status.PublicIPAddress != nil {
			res = append(res, *e.Status.PublicIPAddress)
		}
	}
	return
}

// countReferencedIP counts pods that refer to the kubestatic.quortex.io/externalip label with the desired ip
func countReferencedIP(pods []corev1.Pod, ip string) (count int) {
	for _, e := range pods {
		if e.Labels[externalIPLabel] == ip {
			count++
		}
	}
	return
}

// getMostReferencedIP returns the IP that is the most referenced by the kubestatic.quortex.io/externalip label
func getMostReferencedIP(pods []corev1.Pod, eips []v1alpha1.ExternalIP) (ip *v1alpha1.ExternalIP) {
	count := 0
	for i, e := range eips {
		if c := countReferencedIP(pods, *e.Status.PublicIPAddress); c > count {
			count = c
			ip = &eips[i]
		}
	}
	return
}

const charset = "abcdefghijklmnopqrstuvwxyz"

func randomString(length int) string {
	var seededRand = rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}
