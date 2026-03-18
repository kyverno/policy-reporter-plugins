package events

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/informers"
	k8s "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	kyvernov1 "github.com/kyverno/policy-reporter/kyverno-plugin/pkg/crd/api/kyverno/v1"
	"github.com/kyverno/policy-reporter/kyverno-plugin/pkg/kubernetes/kyverno/ivpol"
	"github.com/kyverno/policy-reporter/kyverno-plugin/pkg/kubernetes/kyverno/pol"
	"github.com/kyverno/policy-reporter/kyverno-plugin/pkg/kubernetes/kyverno/vpol"
	"github.com/kyverno/policy-reporter/kyverno-plugin/pkg/violation"
)

type eventClient struct {
	publisher      *violation.Publisher
	factory        informers.SharedInformerFactory
	client         pol.Client
	vpolClient     vpol.Client
	ivpolClient    ivpol.Client
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

				switch event.InvolvedObject.Kind {
				case "ValidatingPolicy", "NamespacedValidatingPolicy":
					policy, err := e.vpolClient.GetCRD(ctx, event.InvolvedObject.Name, event.InvolvedObject.Namespace)
					if err != nil {
						zap.L().Error("failed to get validatingpolicy", zap.String("policy", event.InvolvedObject.Name), zap.Error(err))
						return
					}

					e.publisher.Publish(ConvertCELPolicyEvent(event, policy, false))
				case "ImageValidatingPolicy", "NamespacedImageValidatingPolicy":
					policy, err := e.ivpolClient.GetCRD(ctx, event.InvolvedObject.Name, event.InvolvedObject.Namespace)
					if err != nil {
						zap.L().Error("failed to get imagevalidatingpolicy", zap.String("policy", event.InvolvedObject.Name), zap.Error(err))
						return
					}

					e.publisher.Publish(ConvertCELPolicyEvent(event, policy, false))
				default:
					policy, err := e.client.GetCRD(ctx, event.InvolvedObject.Name, event.InvolvedObject.Namespace)
					if err != nil {
						zap.L().Error("failed to get policy", zap.String("policy", event.InvolvedObject.Name), zap.Error(err))
						return
					}

					e.publisher.Publish(ConvertPolicyEvent(event, policy, false))
				}
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

				e.publisher.Publish(ConvertPolicyEvent(event, policy, true))
			}
		},
	})

	e.factory.Start(stopper)

	if !cache.WaitForCacheSync(stopper, informer.HasSynced) {
		return fmt.Errorf("failed to sync events")
	}

	return nil
}

func ConvertPolicyEvent(event *corev1.Event, policy kyvernov1.PolicyInterface, updated bool) violation.PolicyViolation {
	parts := strings.Split(event.Message, " ")
	ruleName := strings.TrimSpace(parts[2][1 : len(parts[2])-1])

	var resource violation.Resource
	if event.Related != nil {
		resource = violation.Resource{
			Kind:       event.Related.Kind,
			Namespace:  event.Related.Namespace,
			Name:       event.Related.Name,
			APIVersion: event.Related.APIVersion,
		}
	} else {
		resourceParts := strings.Split(parts[1][0:len(parts[1])-1], "/")

		var namespace, name string
		if len(resourceParts) == 2 {
			namespace = strings.TrimSpace(resourceParts[0])
			name = strings.TrimSpace(resourceParts[1])
		} else {
			name = strings.TrimSpace(resourceParts[0])
		}

		resource = violation.Resource{
			Kind:      strings.TrimSpace(parts[0]),
			Namespace: namespace,
			Name:      name,
		}
	}

	message := event.Message
	for _, rule := range policy.GetSpec().Rules {
		if rule.Name == ruleName && rule.HasValidate() {
			message = rule.Validation.Message
		}
	}

	timestamp := event.LastTimestamp.Time
	if timestamp.IsZero() {
		timestamp = time.Now()
	}

	name := policy.GetName()
	if policy.GetNamespace() != "" {
		name = fmt.Sprintf("%s/%s", policy.GetNamespace(), policy.GetName())
	}

	return violation.PolicyViolation{
		Resource: resource,
		Policy: violation.Policy{
			Name:     name,
			Rule:     ruleName,
			Message:  message,
			Category: policy.GetAnnotations()[pol.AnnotationPolicyCategory],
			Severity: policy.GetAnnotations()[pol.AnnotationPolicySeverity],
		},
		Timestamp: timestamp,
		Updated:   updated,
		Event: violation.Event{
			Name: event.Name,
			UID:  string(event.UID),
		},
	}
}

func ConvertCELPolicyEvent(event *corev1.Event, policy metav1.Object, updated bool) violation.PolicyViolation {
	message := event.Message

	splits := strings.Split(event.Message, "(blocked); ")
	if len(splits) == 2 {
		message = strings.TrimSpace(splits[1])
	}

	timestamp := event.LastTimestamp.Time
	if timestamp.IsZero() {
		timestamp = time.Now()
	}

	var resource violation.Resource
	if event.Related != nil {
		resource = violation.Resource{
			Kind:       event.Related.Kind,
			Namespace:  event.Related.Namespace,
			Name:       event.Related.Name,
			APIVersion: event.Related.APIVersion,
		}
	} else {
		parts := strings.Split(event.Message, " ")
		resourceParts := strings.Split(parts[1][0:len(parts[1])-1], "/")

		var namespace, name string
		if len(resourceParts) == 2 {
			namespace = strings.TrimSpace(resourceParts[0])
			name = strings.TrimSpace(resourceParts[1])
		} else {
			name = strings.TrimSpace(resourceParts[0])
		}

		resource = violation.Resource{
			Kind:      strings.TrimSpace(parts[0]),
			Namespace: namespace,
			Name:      name,
		}
	}

	name := policy.GetName()
	if policy.GetNamespace() != "" {
		name = fmt.Sprintf("%s/%s", policy.GetNamespace(), policy.GetName())
	}

	return violation.PolicyViolation{
		Resource: resource,
		Policy: violation.Policy{
			Kind:     event.InvolvedObject.Kind,
			Name:     name,
			Rule:     "",
			Message:  message,
			Category: policy.GetAnnotations()[pol.AnnotationPolicyCategory],
			Severity: policy.GetAnnotations()[pol.AnnotationPolicySeverity],
		},
		Timestamp: timestamp,
		Updated:   updated,
		Event: violation.Event{
			Name: event.Name,
			UID:  string(event.UID),
		},
	}
}

func NewClient(events k8s.Interface, publisher *violation.Publisher, client pol.Client, vpolClient vpol.Client, ivpolClient ivpol.Client, eventNamespace string) violation.EventClient {
	factory := informers.NewSharedInformerFactoryWithOptions(events, 0, informers.WithNamespace(eventNamespace), informers.WithTweakListOptions(func(lo *v1.ListOptions) {
		lo.FieldSelector = fields.Set{
			"source": "kyverno-admission",
			"reason": "PolicyViolation",
			"type":   "Warning",
		}.AsSelector().String()
	}))

	return &eventClient{
		publisher:   publisher,
		factory:     factory,
		client:      client,
		vpolClient:  vpolClient,
		ivpolClient: ivpolClient,
	}
}
