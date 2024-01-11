package events_test

import (
	"context"
	"sync"
	"testing"
	"time"

	sdk "github.com/kyverno/policy-reporter-plugins/sdk/api"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	k8s "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	eventsv1 "k8s.io/client-go/kubernetes/typed/core/v1"

	kyvernov1 "github.com/kyverno/policy-reporter-plugins/plugins/kyverno/pkg/crd/api/kyverno/v1"
	kubernetes "github.com/kyverno/policy-reporter-plugins/plugins/kyverno/pkg/kubernetes/events"
	"github.com/kyverno/policy-reporter-plugins/plugins/kyverno/pkg/kubernetes/kyverno"
	"github.com/kyverno/policy-reporter-plugins/plugins/kyverno/pkg/violation"
)

var (
	createdAt = v1.NewTime(time.Now().Add(1 * time.Minute))
	updatedAt = v1.NewTime(time.Now().Add(2 * time.Minute))

	baseEvent = &corev1.Event{
		ObjectMeta: v1.ObjectMeta{
			Name:              "nginx.12345",
			Namespace:         "default",
			UID:               "27d99ed6-2535-4a6b-a33a-dea49062fdcd",
			CreationTimestamp: createdAt,
		},
		InvolvedObject: corev1.ObjectReference{
			Name: "require-request-and-limits",
			UID:  "1f2b937f-8ae9-4071-aa37-4d35c87965a3",
		},
		Source: corev1.EventSource{
			Component: "kyverno-admission",
		},
		Message:       "Pod test/nginx: [require-resource-request] fail (blocked)",
		Reason:        "PolicyViolation",
		Type:          "Warning",
		LastTimestamp: updatedAt,
	}

	basePolicy = kyvernov1.ClusterPolicy{
		TypeMeta: v1.TypeMeta{
			APIVersion: "kyverno.io/v1",
			Kind:       "ClusterPolicy",
		},
		ObjectMeta: v1.ObjectMeta{
			Name: "require-request-and-limits",
			UID:  types.UID("1f2b937f-8ae9-4071-aa37-4d35c87965a3"),
			Annotations: map[string]string{
				kyverno.AnnotationPolicyCategory: "Best Practices",
				kyverno.AnnotationPolicySeverity: "medium",
			},
			CreationTimestamp: v1.Now(),
		},
		Spec: kyvernov1.Spec{
			Rules: []kyvernov1.Rule{
				{
					Name: "require-resource-request",
					Validation: kyvernov1.Validation{
						Message: "test message",
					},
				},
			},
		},
	}
)

func NewEventFakeCilent() (k8s.Interface, eventsv1.EventInterface) {
	client := fake.NewSimpleClientset()

	return client, client.CoreV1().Events("default")
}

type policyFakeClient struct{}

func (c *policyFakeClient) GetPolicies(ctx context.Context) ([]sdk.PolicyListItem, error) {
	return nil, nil
}

func (c *policyFakeClient) GetPolicy(ctx context.Context, name string) (*sdk.Policy, error) {
	return nil, nil
}

func (c *policyFakeClient) GetCRD(ctx context.Context, name, namespace string) (kyvernov1.PolicyInterface, error) {
	return &basePolicy, nil
}

func NewPolicyFakeCilent() kyverno.Client {
	return &policyFakeClient{}
}

type eventStore struct {
	store []violation.PolicyViolation
	rwm   *sync.RWMutex
}

func (s *eventStore) Add(r violation.PolicyViolation) {
	s.rwm.Lock()
	s.store = append(s.store, r)
	s.rwm.Unlock()
}

func (s *eventStore) Get(index int) violation.PolicyViolation {
	return s.store[index]
}

func (s *eventStore) List() []violation.PolicyViolation {
	return s.store
}

func newEventStore(size int) *eventStore {
	return &eventStore{
		store: make([]violation.PolicyViolation, 0, size),
		rwm:   &sync.RWMutex{},
	}
}

func Test_EventWatcher(t *testing.T) {
	ctx := context.Background()
	stop := make(chan struct{})
	defer close(stop)

	kclient, pclient := NewEventFakeCilent()

	eventChan := make(chan violation.PolicyViolation)

	publisher := violation.NewPublisher()
	publisher.RegisterListener(func(pv violation.PolicyViolation) {
		eventChan <- pv
	})

	client := kubernetes.NewClient(kclient, publisher, NewPolicyFakeCilent(), "default")
	err := client.Run(ctx, stop)
	if err != nil {
		t.Fatal(err)
	}

	store := newEventStore(3)

	t.Run("AddListener", func(t *testing.T) {
		_, _ = pclient.Create(ctx, baseEvent, v1.CreateOptions{})

		violation := <-eventChan

		store.Add(violation)

		if len(store.List()) != 1 {
			t.Error("Should receive Add Event")
		}

		checkViolationPolicy(violation, t)
		checkViolationResource(violation, t)
		checkViolationEvent(violation, baseEvent, t)
	})

	t.Run("UpdateListener", func(t *testing.T) {
		event := baseEvent.DeepCopy()
		event.LastTimestamp = v1.Now()

		_, _ = pclient.Update(ctx, event, v1.UpdateOptions{})

		violation := <-eventChan

		store.Add(violation)

		if len(store.List()) != 2 {
			t.Error("Should receive Update Event")
		}

		checkViolationPolicy(violation, t)
		checkViolationResource(violation, t)
		checkViolationEvent(violation, event, t)
	})

	t.Run("ClusterResource Event", func(t *testing.T) {
		event := baseEvent.DeepCopy()
		event.Message = "Namespace test: [require-resource-request] fail (blocked)"
		event.UID = "58ee457c-465b-482a-a965-b206fe8567bd"

		_, _ = pclient.Update(ctx, event, v1.UpdateOptions{})

		violation := <-eventChan

		store.Add(violation)

		if len(store.List()) != 3 {
			t.Error("Should receive Add Event")
		}

		checkViolationPolicy(violation, t)
		checkViolationEvent(violation, event, t)

		if violation.Resource.Kind != "Namespace" {
			t.Errorf("expected Resource.Kind to be '%s', got %s", "Namespace", violation.Resource.Kind)
		}
		if violation.Resource.Name != "test" {
			t.Errorf("expected Resource.Name to be '%s', got %s", "test", violation.Resource.Name)
		}
		if violation.Resource.Namespace != "" {
			t.Errorf("expected Resource.Namespace to be '%s', got %s", "", violation.Resource.Namespace)
		}
	})

	t.Run("Ignore none blocked events", func(t *testing.T) {
		event := baseEvent.DeepCopy()
		event.Message = "Namespace test: [require-resource-request] fail"
		event.LastTimestamp = v1.Now()

		_, _ = pclient.Create(ctx, event, v1.CreateOptions{})
	})
}

func Test_NotBlockedEvent(t *testing.T) {
	ctx := context.Background()
	stop := make(chan struct{})
	defer close(stop)

	kclient, pclient := NewEventFakeCilent()

	eventChan := make(chan violation.PolicyViolation)

	publisher := violation.NewPublisher()
	publisher.RegisterListener(func(pv violation.PolicyViolation) {
		eventChan <- pv
	})

	client := kubernetes.NewClient(kclient, publisher, NewPolicyFakeCilent(), "default")
	err := client.Run(ctx, stop)
	if err != nil {
		t.Fatal(err)
	}

	event := baseEvent.DeepCopy()
	event.Message = "Namespace test: [require-resource-request] fail"
	event.LastTimestamp = v1.Now()

	_, _ = pclient.Create(ctx, event, v1.CreateOptions{})
	time.Sleep(1 * time.Millisecond)
	_, _ = pclient.Update(ctx, event, v1.UpdateOptions{})

	go func() {
		<-eventChan
		t.Error("Should not receive new event")
	}()

	time.Sleep(1 * time.Second)
}

func Test_UnknownPolicy(t *testing.T) {
	ctx := context.Background()
	stop := make(chan struct{})
	defer close(stop)

	kclient, pclient := NewEventFakeCilent()

	eventChan := make(chan violation.PolicyViolation)

	publisher := violation.NewPublisher()
	publisher.RegisterListener(func(pv violation.PolicyViolation) {
		eventChan <- pv
	})

	client := kubernetes.NewClient(kclient, publisher, NewPolicyFakeCilent(), "default")
	err := client.Run(ctx, stop)
	if err != nil {
		t.Fatal(err)
	}

	event := baseEvent.DeepCopy()
	event.InvolvedObject.Name = "unknown"
	event.InvolvedObject.UID = "4baaf7cc-4f7c-4746-b8e3-1dd7cc002c75"

	_, _ = pclient.Create(ctx, event, v1.CreateOptions{})
	time.Sleep(1 * time.Millisecond)
	_, _ = pclient.Update(ctx, event, v1.UpdateOptions{})

	go func() {
		<-eventChan
		t.Error("Should not receive new event")
	}()

	time.Sleep(1 * time.Second)
}

func checkViolationPolicy(violation violation.PolicyViolation, t *testing.T) {
	category := basePolicy.GetAnnotations()[kyverno.AnnotationPolicyCategory]
	severity := basePolicy.GetAnnotations()[kyverno.AnnotationPolicySeverity]
	rule := basePolicy.GetSpec().Rules[0]

	if violation.Policy.Category != category {
		t.Errorf("expected Category to be '%s', got %s", category, violation.Policy.Category)
	}
	if violation.Policy.Severity != severity {
		t.Errorf("expected Severity to be '%s', got %s", severity, violation.Policy.Severity)
	}
	if violation.Policy.Name != basePolicy.Name {
		t.Errorf("expected Policy to be '%s', got %s", basePolicy.Name, violation.Policy.Name)
	}
	if violation.Policy.Rule != rule.Name {
		t.Errorf("expected Rule to be '%s', got %s", rule.Name, violation.Policy.Rule)
	}
	if violation.Policy.Message != rule.Validation.Message {
		t.Errorf("expected Message to be '%s', got %s", rule.Validation.Message, violation.Policy.Message)
	}
}

func checkViolationResource(violation violation.PolicyViolation, t *testing.T) {
	if violation.Resource.Kind != "Pod" {
		t.Errorf("expected Resource.Kind to be '%s', got %s", "Pod", violation.Resource.Kind)
	}
	if violation.Resource.Name != "nginx" {
		t.Errorf("expected Resource.Name to be '%s', got %s", "nginx", violation.Resource.Name)
	}
	if violation.Resource.Namespace != "test" {
		t.Errorf("expected Resource.Namespace to be '%s', got %s", "test", violation.Resource.Namespace)
	}
}

func checkViolationEvent(violation violation.PolicyViolation, event *corev1.Event, t *testing.T) {
	if violation.Event.Name != event.Name {
		t.Errorf("expected Event.Name to be '%s', got %s", event.Name, violation.Event.Name)
	}
	if violation.Event.UID != string(event.UID) {
		t.Errorf("expected Event.UID to be '%s', got %s", event.UID, violation.Event.UID)
	}
}
