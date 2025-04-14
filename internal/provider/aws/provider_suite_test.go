package aws

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
	"github.com/onsi/gomega/types"
	kmetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// MatchCondition returns a custom Gomega matcher to check the fields of a Kubernetes condition.
//
// Parameters:
//   - obj: The Kubernetes condition to be matched.
//   - ignoredFields: A variadic list of field names to be ignored in the match.
//
// Returns:
//   - A GomegaMatcher that matches the fields of the provided Kubernetes condition.
func MatchCondition(obj kmetav1.Condition, ignoredFields ...string) types.GomegaMatcher {
	fields := Fields{
		"Type":               BeEquivalentTo(obj.Type),
		"Status":             BeEquivalentTo(obj.Status),
		"ObservedGeneration": BeComparableTo(obj.ObservedGeneration),
		"LastTransitionTime": BeComparableTo(obj.LastTransitionTime),
		"Reason":             BeComparableTo(obj.Reason),
		"Message":            BeComparableTo(obj.Message),
	}

	for _, ignoredField := range ignoredFields {
		delete(fields, ignoredField)
	}
	return MatchFields(IgnoreExtras, fields)
}

// MatchConditions returns a slice of custom Gomega matchers to check the fields of multiple Kubernetes conditions.
//
// Parameters:
//   - obj: A slice of Kubernetes conditions to be matched.
//   - ignoredFields: A variadic list of field names to be ignored in the match.
//
// Returns:
//   - A slice of GomegaMatchers that match the fields of the provided Kubernetes conditions.
func MatchConditions(obj []kmetav1.Condition, ignoredFields ...string) []types.GomegaMatcher {
	res := make([]types.GomegaMatcher, len(obj))
	for i, condition := range obj {
		res[i] = MatchCondition(condition, ignoredFields...)
	}
	return res
}

func TestAwsProvider(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Aws Provider Suite")
}
