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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/quortex/kubestatic/api/v1alpha1"
	"github.com/quortex/kubestatic/internal/provider"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ = Describe("Node Controller", func() {

	const timeout = time.Second * 30
	const interval = time.Second * 1

	BeforeEach(func() {
		// Add any setup steps that needs to be executed before each test
	})

	AfterEach(func() {
		// Add any teardown steps that needs to be executed after each test
	})

	Context("Node with external ip automatic assignment label", func() {
		It("Should be assigned an ExternalIP", func() {
			node := safeDequeueNode()

			By("Expecting that no ExternalIP is assigned to the Node at the start")
			// Check if no ExternalIP is assigned to the Node
			externalIPs := &v1alpha1.ExternalIPList{}
			Expect(k8sClient.List(context.Background(), externalIPs, client.MatchingFields{externalIPNodeNameField: node.Name}))
			Expect(externalIPs.Items).To(BeEmpty())

			By("Expecting to add auto IP assign labels on node")
			// Add auto assign label on Node

			original := node.DeepCopy()
			node.Labels[externalIPAutoAssignLabel] = "true"
			k8sClient.Patch(context.Background(), &node, client.MergeFrom(original))
			// node.Labels[externalIPAutoAssignLabel] = "true"
			// Eventually(func() bool {
			// 	err := k8sClient.Update(context.Background(), &node)
			// 	return err == nil
			// }, timeout, interval).Should(BeTrue())

			By("Expecting that an ExternalIP is assigned to Node")
			// Wait for an ExternalIP to be attached to the Node
			Eventually(func() bool {
				err := k8sClient.List(context.Background(), externalIPs, client.MatchingFields{externalIPNodeNameField: node.Name})
				if err != nil {
					return false
				}
				return len(externalIPs.Items) == 1 && externalIPs.Items[0].IsAssociated()
			}, timeout, interval).Should(BeTrue())
			externalIP := externalIPs.Items[0]
			Expect(externalIP.Status.AddressID).ToNot(BeNil(), assertionDescription("ExternalIP", externalIP.Name, "status.addressID"))
			addressID := *externalIP.Status.AddressID

			By("Expecting to remove auto IP assign labels on node")

			original = node.DeepCopy()
			node.Labels[externalIPAutoAssignLabel] = "false"
			k8sClient.Patch(context.Background(), &node, client.MergeFrom(original))

			// patch = []byte(`{"metadata":{"labels":{externalIPAutoAssignLabel: "false"}}}`)
			// Expect(k8sClient.Patch(context.Background(), &node, client.RawPatch(types.StrategicMergePatchType, patch)))

			// delete(node.Labels, externalIPAutoAssignLabel)
			// Eventually(func() bool {
			// 	err := k8sClient.Update(context.Background(), &node)
			// 	return err == nil
			// }, timeout, interval).Should(BeTrue())

			By("Deleting the ExternalIP successfully")
			// Delete created ExternalIP and check that provider externalIP no longer exists
			fetched := &v1alpha1.ExternalIP{}
			Expect(k8sClient.Delete(context.Background(), &externalIP)).Should(Succeed())
			Eventually(func() bool {
				err := k8sClient.Get(context.Background(), types.NamespacedName{
					Name: externalIP.Name,
				}, fetched)
				return errors.IsNotFound(err)
			}, timeout, interval).Should(BeTrue())
			Eventually(func() bool {
				_, err := pvd.GetAddress(context.Background(), addressID)
				return provider.IsErrNotFound(err)
			}, timeout, interval).Should(BeTrue())
		})
	})
})
