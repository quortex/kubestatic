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
	"fmt"
	"log"
	"math/rand"
	"path/filepath"
	"sync"
	"testing"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/envtest/printer"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"quortex.io/kubestatic/api/v1alpha1"
	"quortex.io/kubestatic/pkg/provider"
	"quortex.io/kubestatic/pkg/provider/aws"
	//+kubebuilder:scaffold:imports
)

// These tests use Ginkgo (BDD-style Go testing framework). Refer to
// http://onsi.github.io/ginkgo/ to learn more about Ginkgo.

var cfg *rest.Config
var k8sClient client.Client
var k8sManager ctrl.Manager
var pvd provider.Provider
var testEnv *envtest.Environment
var nodes []corev1.Node
var mu sync.Mutex

func TestAPIs(t *testing.T) {
	RegisterFailHandler(Fail)

	RunSpecsWithDefaultAndCustomReporters(t,
		"Controller Suite",
		[]Reporter{printer.NewlineReporter{}})
}

var _ = BeforeSuite(func(done Done) {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))

	By("bootstrapping test environment")
	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}

	cfg, err := testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(cfg).NotTo(BeNil())

	err = v1alpha1.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())

	//+kubebuilder:scaffold:scheme

	k8sManager, err = ctrl.NewManager(cfg, ctrl.Options{
		Scheme: scheme.Scheme,
	})
	Expect(err).ToNot(HaveOccurred())

	pvd = aws.NewProvider()

	err = (&ExternalIPReconciler{
		Client:   k8sManager.GetClient(),
		Log:      ctrl.Log.WithName("controllers").WithName("ExternalIP"),
		Scheme:   k8sManager.GetScheme(),
		Provider: pvd,
	}).SetupWithManager(k8sManager)
	Expect(err).ToNot(HaveOccurred())

	err = (&NodeReconciler{
		Client: k8sManager.GetClient(),
		Log:    ctrl.Log.WithName("controllers").WithName("Node"),
		Scheme: k8sManager.GetScheme(),
	}).SetupWithManager(k8sManager)
	Expect(err).ToNot(HaveOccurred())

	err = (&FirewallRuleReconciler{
		Client:   k8sManager.GetClient(),
		Log:      ctrl.Log.WithName("controllers").WithName("FirewallRule"),
		Scheme:   k8sManager.GetScheme(),
		Provider: pvd,
	}).SetupWithManager(k8sManager)
	Expect(err).ToNot(HaveOccurred())

	go func() {
		err = k8sManager.Start(ctrl.SetupSignalHandler())
		Expect(err).ToNot(HaveOccurred())
	}()

	k8sClient = k8sManager.GetClient()
	Expect(k8sClient).ToNot(BeNil())

	time.Sleep(time.Second * 5)

	// List all nodes once for all tests
	nodeList := &corev1.NodeList{}
	Eventually(func() bool {
		err := k8sClient.List(
			context.Background(),
			nodeList,
		)
		// log.Printf("%v", err)
		return err == nil
	}, 60, 4).Should(BeTrue())
	nodes = nodeList.Items

	// log.Printf("%v", nodeList)

	close(done)
}, 60)

var _ = AfterSuite(func() {
	By("tearing down the test environment")
	gexec.KillAndWait(5 * time.Second)

	err := testEnv.Stop()
	Expect(err).ToNot(HaveOccurred())
})

const charset = "abcdefghijklmnopqrstuvwxyz"

func randomStringWithCharset(length int, charset string) string {
	var seededRand = rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

// isReady returns if the node Status is Ready
func isReady(node corev1.Node) bool {
	for _, e := range node.Status.Conditions {
		if e.Type == corev1.NodeReady {
			return e.Status == corev1.ConditionTrue
		}
	}
	return false
}

// dequeueNode pick a Ready node in the list
func dequeueNode() corev1.Node {
	log.Print("dequeueNode")
	n := nodes[0]
	nodes = nodes[1:]
	if !isReady(n) {
		return dequeueNode()
	}
	return n
}

// safeDequeueNode pick a Ready node in the list
func safeDequeueNode() corev1.Node {
	mu.Lock()
	defer mu.Unlock()
	return dequeueNode()
}

func assertionDescription(kind, name, field string) string {
	return fmt.Sprintf("%s %s %s", kind, name, field)
}
