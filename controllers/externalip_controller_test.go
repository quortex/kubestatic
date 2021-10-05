//go:build e2e

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
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"quortex.io/kubestatic/api/v1alpha1"
	"quortex.io/kubestatic/pkg/provider"
)

var _ = Describe("ExternalIP Controller", func() {

	const timeout = time.Second * 30
	const interval = time.Second * 1

	BeforeEach(func() {
		// Add any setup steps that needs to be executed before each test
	})

	AfterEach(func() {
		// Add any teardown steps that needs to be executed after each test
	})

	Context("ExternalIP on Node", func() {
		It("Should associate an externalIP correctly", func() {
			node := safeDequeueNode()
			key := types.NamespacedName{
				Name: "external-ip-" + randomStringWithCharset(10, charset),
			}

			toCreate := &v1alpha1.ExternalIP{
				ObjectMeta: metav1.ObjectMeta{
					Name:      key.Name,
					Namespace: key.Namespace,
				},
				Spec: v1alpha1.ExternalIPSpec{
					NodeName: node.Name,
				},
			}

			By("Creating the ExternalIP successfully")
			// Check if ExternalIP is successfully created and associated
			fetched := &v1alpha1.ExternalIP{}
			Expect(k8sClient.Create(context.Background(), toCreate)).Should(Succeed())
			Eventually(func() bool {
				_ = k8sClient.Get(context.Background(), key, fetched)
				return fetched.IsAssociated()
			}, timeout, interval).Should(BeTrue())

			By("Expecting ExternalIP address status to comply with the provider")
			// Retrieve addressID from status
			Expect(fetched.Status.AddressID).ToNot(BeNil(), assertionDescription("ExternalIP", fetched.Name, "status.addressID"))
			addressID := *fetched.Status.AddressID

			// Retrieve publicIP from status
			Expect(fetched.Status.PublicIPAddress).ToNot(BeNil(), assertionDescription("ExternalIP", fetched.Name, "status.publicIPAddress"))
			publicIPAddress := *fetched.Status.PublicIPAddress

			// Retrieve associated IP and check ExternalIP reliability
			Eventually(func() bool {
				addr, err := pvd.GetAddress(context.Background(), addressID)
				if err != nil {
					return false
				}
				return addr.PublicIP == publicIPAddress
			}, timeout, interval).Should(BeTrue())

			By("Expecting ExternalIP instance status to comply with the provider")
			// Retrieve instanceID from status
			Expect(fetched.Status.InstanceID).ToNot(BeNil(), assertionDescription("ExternalIP", fetched.Name, "status.instanceID"))
			instanceID := *fetched.Status.InstanceID

			// Retrieve associated instance and check ExternalIP reliability
			var instance *provider.Instance
			Eventually(func() bool {
				var err error
				instance, err = pvd.GetInstance(context.Background(), instanceID)
				return err == nil
			}, timeout, interval).Should(BeTrue())
			Expect(instance.NetworkInterfaces[0].PublicIP).ToNot(BeNil())
			Expect(publicIPAddress).To(Equal(*instance.NetworkInterfaces[0].PublicIP), assertionDescription("ExternalIP", fetched.Name, "status.publicIPAddress"))

			By("Deleting the ExternalIP successfully")
			// Delete created ExternalIP and check that provider externalIP no longer exists
			Expect(k8sClient.Delete(context.Background(), toCreate)).Should(Succeed())
			Eventually(func() bool {
				err := k8sClient.Get(context.Background(), key, fetched)
				return errors.IsNotFound(err)
			}, timeout, interval).Should(BeTrue())
			Eventually(func() bool {
				_, err := pvd.GetAddress(context.Background(), addressID)
				return provider.IsErrNotFound(err)
			}, timeout, interval).Should(BeTrue())
		})
	})
})
