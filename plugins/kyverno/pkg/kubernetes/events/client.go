package events

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/informers"
	k8s "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	kyvernov1 "github.com/kyverno/policy-reporter/kyverno-plugin/pkg/crd/api/kyverno/v1"
	"github.com/kyverno/policy-reporter/kyverno-plugin/pkg/kubernetes/kyverno"
	"github.com/kyverno/policy-reporter/kyverno-plugin/pkg/violation"
)

type eventClient struct {
	publisher      *violation.Publisher
	factory        informers.SharedInformerFactory
	client         kyverno.Client
	eventNamespace string
}

func (e *eventClient) Run(ctx context.Context, stopper chan struct{}) error {
	startUp := time.Now()
	informer := e.factory.Core().V1().Events().Informer()

	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			if event, ok := obj.(*corev1.Event); ok {
				if !strings.Contains(event.Message, "(blocked)") || startUp.After(event.CreationTimestamp.Time) {
					return
				}

				policy, err := e.client.GetCRD(ctx, event.InvolvedObject.Name, event.InvolvedObject.Namespace)
				if err != nil {
					zap.L().Error("failed to get policy", zap.String("policy", event.InvolvedObject.Name), zap.Error(err))
					return
				}

				e.publisher.Publish(ConvertEvent(event, policy, false))
			}
		},
		UpdateFunc: func(old interface{}, obj interface{}) {
			if event, ok := obj.(*corev1.Event); ok {
				if !strings.Contains(event.Message, "(blocked)") || startUp.After(event.LastTimestamp.Time) {
					return
				}

				policy, err := e.client.GetCRD(ctx, event.InvolvedObject.Name, event.InvolvedObject.Namespace)
				if err != nil {
					zap.L().Error("failed to get policy", zap.String("policy", event.InvolvedObject.Name), zap.Error(err))
					return
				}

				e.publisher.Publish(ConvertEvent(event, policy, true))
			}
		},
	})

	e.factory.Start(stopper)

	if !cache.WaitForCacheSync(stopper, informer.HasSynced) {
		return fmt.Errorf("failed to sync events")
	}

	return nil
}

func ConvertEvent(event *corev1.Event, policy kyvernov1.PolicyInterface, updated bool) violation.PolicyViolation {
	parts := strings.Split(event.Message, " ")
	resourceParts := strings.Split(parts[1][0:len(parts[1])-1], "/")

	var namespace, name string

	if len(resourceParts) == 2 {
		namespace = strings.TrimSpace(resourceParts[0])
		name = strings.TrimSpace(resourceParts[1])
	} else {
		name = strings.TrimSpace(resourceParts[0])
	}

	ruleName := strings.TrimSpace(parts[2][1 : len(parts[2])-1])

	message := event.Message
	for _, rule := range policy.GetSpec().Rules {
		if rule.Name == ruleName && rule.HasValidate() {
			message = rule.Validation.Message
		}
	}

	return violation.PolicyViolation{
		Resource: violation.Resource{
			Kind:      strings.TrimSpace(parts[0]),
			Namespace: namespace,
			Name:      name,
		},
		Policy: violation.Policy{
			Name:     policy.GetName(),
			Rule:     ruleName,
			Message:  message,
			Category: policy.GetAnnotations()[kyverno.AnnotationPolicyCategory],
			Severity: policy.GetAnnotations()[kyverno.AnnotationPolicySeverity],
		},
		Timestamp: event.LastTimestamp.Time,
		Updated:   updated,
		Event: violation.Event{
			Name: event.Name,
			UID:  string(event.UID),
		},
	}
}

func NewClient(events k8s.Interface, publisher *violation.Publisher, client kyverno.Client, eventNamespace string) violation.EventClient {
	factory := informers.NewFilteredSharedInformerFactory(events, 0, eventNamespace, func(lo *v1.ListOptions) {
		lo.FieldSelector = fields.Set{
			"source": "kyverno-admission",
			"reason": "PolicyViolation",
			"type":   "Warning",
		}.AsSelector().String()
	})

	return &eventClient{
		publisher: publisher,
		factory:   factory,
		client:    client,
	}
}
