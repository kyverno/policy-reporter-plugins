/*
Copyright The Kubernetes Authors.

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

// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	v1alpha1 "github.com/kyverno/policy-reporter/kyverno-plugin/pkg/crd/api/policies.kyverno.io/v1alpha1"
	policieskyvernoiov1alpha1 "github.com/kyverno/policy-reporter/kyverno-plugin/pkg/crd/client/clientset/versioned/typed/policies.kyverno.io/v1alpha1"
	gentype "k8s.io/client-go/gentype"
)

// fakeImageValidatingPolicies implements ImageValidatingPolicyInterface
type fakeImageValidatingPolicies struct {
	*gentype.FakeClientWithList[*v1alpha1.ImageValidatingPolicy, *v1alpha1.ImageValidatingPolicyList]
	Fake *FakePoliciesV1alpha1
}

func newFakeImageValidatingPolicies(fake *FakePoliciesV1alpha1) policieskyvernoiov1alpha1.ImageValidatingPolicyInterface {
	return &fakeImageValidatingPolicies{
		gentype.NewFakeClientWithList[*v1alpha1.ImageValidatingPolicy, *v1alpha1.ImageValidatingPolicyList](
			fake.Fake,
			"",
			v1alpha1.SchemeGroupVersion.WithResource("imagevalidatingpolicies"),
			v1alpha1.SchemeGroupVersion.WithKind("ImageValidatingPolicy"),
			func() *v1alpha1.ImageValidatingPolicy { return &v1alpha1.ImageValidatingPolicy{} },
			func() *v1alpha1.ImageValidatingPolicyList { return &v1alpha1.ImageValidatingPolicyList{} },
			func(dst, src *v1alpha1.ImageValidatingPolicyList) { dst.ListMeta = src.ListMeta },
			func(list *v1alpha1.ImageValidatingPolicyList) []*v1alpha1.ImageValidatingPolicy {
				return gentype.ToPointerSlice(list.Items)
			},
			func(list *v1alpha1.ImageValidatingPolicyList, items []*v1alpha1.ImageValidatingPolicy) {
				list.Items = gentype.FromPointerSlice(items)
			},
		),
		fake,
	}
}
