package secrets

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/client-go/kubernetes/typed/core/v1"

	"github.com/kyverno/policy-reporter-plugins/plugins/trivy/pkg/kubernetes"
)

type Values struct {
	Host        string `json:"api" mapstructure:"api"`
	Certificate string `json:"certificate" mapstructure:"certificate"`
	SkipTLS     bool   `json:"skipTLS" mapstructure:"skipTLS"`
	Username    string `json:"username" mapstructure:"username"`
	Password    string `json:"password" mapstructure:"password"`
}

type Client interface {
	Get(context.Context, string) (Values, error)
}

type k8sClient struct {
	client v1.SecretInterface
}

func (c *k8sClient) Get(ctx context.Context, name string) (Values, error) {
	secret, err := kubernetes.Retry(func() (*corev1.Secret, error) {
		return c.client.Get(ctx, name, metav1.GetOptions{})
	})

	values := Values{}
	if err != nil {
		return values, err
	}

	if api, ok := secret.Data["api"]; ok {
		values.Host = string(api)
	}

	if certificate, ok := secret.Data["certificate"]; ok {
		values.Certificate = string(certificate)
	}

	if username, ok := secret.Data["username"]; ok {
		values.Username = string(username)
	}

	if password, ok := secret.Data["password"]; ok {
		values.Password = string(password)
	}

	return values, nil
}

func NewClient(secretClient v1.SecretInterface) Client {
	return &k8sClient{secretClient}
}
