//go:build e2e
// +build e2e

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
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/quortex/kubestatic/api/v1alpha1"
	"github.com/quortex/kubestatic/pkg/helper"
	"github.com/quortex/kubestatic/pkg/provider"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

var _ = Describe("FirewallRule Controller", func() {

	const timeout = time.Second * 60
	const interval = time.Second * 1

	BeforeEach(func() {
		// Add any setup steps that needs to be executed before each test
	})

	AfterEach(func() {
		// Add any teardown steps that needs to be executed after each test
	})

	Context("FirewallRule on Node", func() {
		It("Should associate a firewall rule correctly", func() {
			node := safeDequeueNode()
			ingressPort := 5678

			By("Retrieving my current IP")
			var myIP string
			Eventually(func() bool {
				res, err := http.Get("http://ifconfig.me")
				if err != nil {
					return false
				}
				defer res.Body.Close()
				body, err := io.ReadAll(res.Body)
				if err != nil {
					return false
				}
				myIP = strings.TrimSuffix(string(body), "\n")
				return true
			}, timeout, interval).Should(BeTrue())
			Expect(myIP).NotTo(BeEmpty())

			By("Creating a FirewallRule successfully on the Node")
			firewallRulekey := types.NamespacedName{
				Name: "firewall-rule-" + randomStringWithCharset(10, charset),
			}
			Expect(k8sClient.Create(context.Background(), &v1alpha1.FirewallRule{
				ObjectMeta: metav1.ObjectMeta{
					Name:      firewallRulekey.Name,
					Namespace: firewallRulekey.Namespace,
				},
				Spec: v1alpha1.FirewallRuleSpec{
					NodeName:    &node.Name,
					Description: "My firewall description",
					Direction:   v1alpha1.DirectionIngress,
					FromPort:    int64(ingressPort),
					Protocol:    "tcp",
					IPRanges: []*v1alpha1.IPRange{
						{
							CIDR: myIP + "/32",
						},
					},
				},
			})).Should(Succeed())

			// Check if FirewallRule is succesfully created and associated
			fetched := &v1alpha1.FirewallRule{}
			Eventually(func() bool {
				_ = k8sClient.Get(context.Background(), firewallRulekey, fetched)
				return fetched.IsAssociated()
			}, timeout, interval).Should(BeTrue())
			Expect(fetched.Status.InstanceID).ToNot(BeNil(), assertionDescription("FirewallRule", fetched.Name, "status.instanceID"))
			Expect(fetched.Status.NetworkInterfaceID).ToNot(BeNil(), assertionDescription("FirewallRule", fetched.Name, "status.networkInterfaceID"))
			networkInterfaceID := *fetched.Status.NetworkInterfaceID

			Expect(fetched.Status.FirewallRuleID).ToNot(BeNil(), assertionDescription("FirewallRule", fetched.Name, "status.firewallRuleID"))
			firewallRuleID := *fetched.Status.FirewallRuleID

			// Retrieve associated instance and check FirewallRule reliability
			var instance *provider.Instance
			Eventually(func() bool {
				var err error
				instance, err = pvd.GetInstance(context.Background(), *fetched.Status.InstanceID)
				return err == nil
			}, timeout, interval).Should(BeTrue())
			Expect(networkInterfaceID).To(Equal(instance.NetworkInterfaces[0].NetworkInterfaceID), assertionDescription("FirewallRule", fetched.Name, "status.networkInterfaceID"))

			By("Creating an ExternalIP sccessfuly on the Node")
			// Attach an ExternalIP to the Node
			externalIPKey := types.NamespacedName{
				Name: "external-ip-" + randomStringWithCharset(10, charset),
			}
			Expect(k8sClient.Create(context.Background(), &v1alpha1.ExternalIP{
				ObjectMeta: metav1.ObjectMeta{
					Name:      externalIPKey.Name,
					Namespace: externalIPKey.Namespace,
				},
				Spec: v1alpha1.ExternalIPSpec{
					NodeName: node.Name,
				},
			})).Should(Succeed())

			By("Expecting to fecth associated ExternalIP")
			fetchedExternalIP := &v1alpha1.ExternalIP{}
			Eventually(func() bool {
				_ = k8sClient.Get(context.Background(), externalIPKey, fetchedExternalIP)
				return fetchedExternalIP.IsAssociated()
			}, timeout, interval).Should(BeTrue())
			Expect(fetchedExternalIP.Status.PublicIPAddress).ToNot(BeNil(), assertionDescription("ExternalIP", fetchedExternalIP.Name, "status.publicIPAddress"))
			externalIPAddress := *fetchedExternalIP.Status.PublicIPAddress
			Expect(fetchedExternalIP.Status.AddressID).ToNot(BeNil(), assertionDescription("ExternalIP", fetchedExternalIP.Name, "status.addressID"))
			addressID := *fetchedExternalIP.Status.AddressID

			By("Expecting to create echo pod exposed on hostPort")
			echoDepKey := types.NamespacedName{
				Name:      "echo-" + randomStringWithCharset(10, charset),
				Namespace: "default",
			}
			echoText := randomStringWithCharset(10, charset)
			echoLabels := map[string]string{
				"app":  "echo",
				"name": echoDepKey.Name,
			}
			Expect(k8sClient.Create(context.Background(), &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      echoDepKey.Name,
					Namespace: echoDepKey.Namespace,
				},
				Spec: appsv1.DeploymentSpec{
					Replicas: helper.Int32Pointer(1),
					Selector: &metav1.LabelSelector{
						MatchLabels: echoLabels,
					},
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Labels: echoLabels,
						},
						Spec: corev1.PodSpec{
							TerminationGracePeriodSeconds: helper.Int64Pointer(0),
							Containers: []corev1.Container{
								{
									Name:  "echo",
									Image: "hashicorp/http-echo",
									Args: []string{
										fmt.Sprintf("-listen=:%d", ingressPort),
										fmt.Sprintf("-text=%s", echoText),
									},
									Ports: []corev1.ContainerPort{
										{
											Name:          "http",
											ContainerPort: int32(ingressPort),
											HostPort:      int32(ingressPort),
										},
									},
								},
							},
							NodeSelector: node.Labels,
						},
					},
				},
			})).Should(Succeed())

			By("Expecting echo pods to run")
			fetchedEchoDep := &appsv1.Deployment{}
			Eventually(func() bool {
				_ = k8sClient.Get(context.Background(), echoDepKey, fetchedEchoDep)
				return fetchedEchoDep.Status.ReadyReplicas == *fetchedEchoDep.Spec.Replicas
			}, timeout, interval).Should(BeTrue())

			By("Expecting requests to hit the echo server")
			var fectedhEchoText string
			Eventually(func() bool {
				res, err := http.Get(fmt.Sprintf("http://%s:%d", externalIPAddress, ingressPort))
				if err != nil {
					return false
				}
				defer res.Body.Close()
				body, err := io.ReadAll(res.Body)
				if err != nil {
					return false
				}
				fectedhEchoText = strings.TrimSuffix(string(body), "\n")
				return true
			}, timeout, interval).Should(BeTrue())
			Expect(fectedhEchoText).To(Equal(echoText))

			By("Deleting the FirewallRule successfully")
			// Delete created FirewallRule and check that provider firewall rule no longer exists
			Expect(k8sClient.Delete(context.Background(), fetched)).Should(Succeed())
			Eventually(func() bool {
				err := k8sClient.Get(context.Background(), firewallRulekey, fetched)
				return errors.IsNotFound(err)
			}, timeout, interval).Should(BeTrue())
			Eventually(func() bool {
				_, err := pvd.GetFirewallRule(context.Background(), firewallRuleID)
				return provider.IsErrNotFound(err)
			}, timeout, interval).Should(BeTrue())

			By("Deleting the ExternalIP successfully")
			// Delete created ExternalIP and check that provider externalIP no longer exists
			Expect(k8sClient.Delete(context.Background(), fetchedExternalIP)).Should(Succeed())
			Eventually(func() bool {
				err := k8sClient.Get(context.Background(), externalIPKey, fetchedExternalIP)
				return errors.IsNotFound(err)
			}, timeout, interval).Should(BeTrue())
			Eventually(func() bool {
				_, err := pvd.GetAddress(context.Background(), addressID)
				return provider.IsErrNotFound(err)
			}, timeout, interval).Should(BeTrue())

			By("Deleting the echo Deployment successfully")
			// Delete created ExternalIP and check that provider externalIP no longer exists
			Expect(k8sClient.Delete(context.Background(), fetchedEchoDep)).Should(Succeed())
			Eventually(func() bool {
				err := k8sClient.Get(context.Background(), echoDepKey, fetchedEchoDep)
				return errors.IsNotFound(err)
			}, timeout, interval).Should(BeTrue())
		})
	})
})
