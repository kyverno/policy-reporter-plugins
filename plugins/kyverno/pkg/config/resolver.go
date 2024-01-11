package config

import (
	"context"
	"time"

	"github.com/gin-gonic/gin"
	gocache "github.com/patrickmn/go-cache"
	"go.uber.org/zap"
	"k8s.io/client-go/dynamic"
	k8s "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/rest"

	"github.com/kyverno/policy-reporter-plugins/plugins/kyverno/pkg/core"
	kyvernov1 "github.com/kyverno/policy-reporter-plugins/plugins/kyverno/pkg/crd/client/clientset/versioned/typed/kyverno/v1"
	"github.com/kyverno/policy-reporter-plugins/plugins/kyverno/pkg/crd/client/clientset/versioned/typed/policyreport/v1alpha2"
	"github.com/kyverno/policy-reporter-plugins/plugins/kyverno/pkg/kubernetes/events"
	"github.com/kyverno/policy-reporter-plugins/plugins/kyverno/pkg/kubernetes/kyverno"
	"github.com/kyverno/policy-reporter-plugins/plugins/kyverno/pkg/kubernetes/leaderelection"
	"github.com/kyverno/policy-reporter-plugins/plugins/kyverno/pkg/kubernetes/policyreport"
	"github.com/kyverno/policy-reporter-plugins/plugins/kyverno/pkg/kubernetes/secrets"
	"github.com/kyverno/policy-reporter-plugins/plugins/kyverno/pkg/logging"
	"github.com/kyverno/policy-reporter-plugins/plugins/kyverno/pkg/server"
	"github.com/kyverno/policy-reporter-plugins/plugins/kyverno/pkg/violation"
)

type Resolver struct {
	config    *Config
	k8sConfig *rest.Config
	clientset *k8s.Clientset

	vPulisher     *violation.Publisher
	secrets       secrets.Client
	leaderClient  *leaderelection.Client
	polrClient    policyreport.Client
	kyvernoClient kyverno.Client
	eventClient   violation.EventClient
}

func (r *Resolver) K8sConfig() (*rest.Config, error) {
	if r.k8sConfig != nil {
		return r.k8sConfig, nil
	}

	var k8sConfig *rest.Config
	var err error

	if r.config.Local {
		k8sConfig, err = RestConfig(r.config.KubeConfig)
	} else {
		k8sConfig, err = rest.InClusterConfig()
	}
	if err != nil {
		return nil, err
	}

	r.k8sConfig = k8sConfig

	return r.k8sConfig, nil
}

func (r *Resolver) Clientset() (*k8s.Clientset, error) {
	if r.clientset != nil {
		return r.clientset, nil
	}

	clientset, err := k8s.NewForConfig(r.k8sConfig)
	if err != nil {
		return nil, err
	}

	r.clientset = clientset

	return r.clientset, nil
}

func (r *Resolver) SecretClient() secrets.Client {
	if r.secrets != nil {
		return r.secrets
	}

	clientset, err := r.Clientset()
	if err != nil {
		return nil
	}

	r.secrets = secrets.NewClient(clientset.CoreV1().Secrets(r.config.Namespace))

	return r.secrets
}

func (r *Resolver) MetadataClient() (metadata.Interface, error) {
	k8sConfig, err := r.K8sConfig()
	if err != nil {
		return nil, err
	}

	client, err := metadata.NewForConfig(k8sConfig)
	if err != nil {
		return nil, err
	}

	return client, nil
}

func (r *Resolver) DynamicClient() (dynamic.Interface, error) {
	k8sConfig, err := r.K8sConfig()
	if err != nil {
		return nil, err
	}

	client, err := dynamic.NewForConfig(k8sConfig)
	if err != nil {
		return nil, err
	}

	return client, nil
}

func (r *Resolver) KyvernoV1Client() (kyvernov1.KyvernoV1Interface, error) {
	k8sConfig, err := r.K8sConfig()
	if err != nil {
		return nil, err
	}

	client, err := kyvernov1.NewForConfig(k8sConfig)
	if err != nil {
		return nil, err
	}

	return client, nil
}

func (r *Resolver) KyvernoClient() (kyverno.Client, error) {
	if r.kyvernoClient != nil {
		return r.kyvernoClient, nil
	}

	m, err := r.MetadataClient()
	if err != nil {
		return nil, err
	}

	d, err := r.DynamicClient()
	if err != nil {
		return nil, err
	}

	k, err := r.KyvernoV1Client()
	if err != nil {
		return nil, err
	}

	r.kyvernoClient = kyverno.NewClient(m, d, k, gocache.New(15*time.Second, 5*time.Second))

	return r.kyvernoClient, nil
}

func (r *Resolver) Logger() *zap.Logger {
	return logging.New(r.config.Logging)
}

func (r *Resolver) Server(ctx context.Context, options []server.ServerOption) (*server.Server, error) {
	var err error
	basicAuth := &r.config.Server.BasicAuth

	if basicAuth.SecretRef != "" {
		if basicAuth, err = r.LoadBasicAuth(ctx, r.config.Server.BasicAuth.SecretRef); err != nil {
			zap.L().Error("failed to load basic auth secret", zap.Error(err))
		}
	}

	if basicAuth.Username != "" && basicAuth.Password != "" {
		options = append(options, server.WithBasicAuth(server.BasicAuth{
			Username: basicAuth.Username,
			Password: basicAuth.Password,
		}))
	}

	if !r.config.Server.Debug {
		gin.SetMode(gin.ReleaseMode)
	}

	engine := gin.New()
	defaults := []server.ServerOption{server.WithGZIP()}

	if r.config.Logging.Enabled || r.config.Server.Debug {
		defaults = append(defaults, server.WithLogging(zap.L()))
	} else {
		defaults = append(defaults, server.WithRecovery())
	}

	serv := server.NewServer(engine, append(defaults, options...))

	return serv, nil
}

func (r *Resolver) ViolationPublisher() *violation.Publisher {
	if r.vPulisher != nil {
		return r.vPulisher
	}

	r.vPulisher = violation.NewPublisher()

	return r.vPulisher
}

func (r *Resolver) EventClient() (violation.EventClient, error) {
	if r.eventClient != nil {
		return r.eventClient, nil
	}

	clientset, err := r.Clientset()
	if err != nil {
		return nil, err
	}

	kclient, err := r.KyvernoClient()
	if err != nil {
		return nil, err
	}

	r.eventClient = events.NewClient(clientset, r.ViolationPublisher(), kclient, r.config.BlockReports.EventNamespace)

	return r.eventClient, nil
}

func (r *Resolver) PolicyReportClient() (policyreport.Client, error) {
	if r.polrClient != nil {
		return r.polrClient, nil
	}

	client, err := v1alpha2.NewForConfig(r.k8sConfig)
	if err != nil {
		return nil, err
	}

	policyreportClient := policyreport.NewClient(
		client,
		r.config.BlockReports.Results.MaxPerReport,
		r.config.BlockReports.Source,
		r.config.BlockReports.Results.KeepOnlyLatest,
	)

	r.polrClient = policyreportClient

	return policyreportClient, nil
}

func (r *Resolver) LeaderElectionClient() (*leaderelection.Client, error) {
	if r.leaderClient != nil {
		return r.leaderClient, nil
	}

	clientset, err := r.Clientset()
	if err != nil {
		return nil, err
	}

	r.leaderClient = leaderelection.New(
		clientset.CoordinationV1(),
		r.config.LeaderElection.LockName,
		r.config.Namespace,
		r.config.LeaderElection.PodName,
		time.Duration(r.config.LeaderElection.LeaseDuration)*time.Second,
		time.Duration(r.config.LeaderElection.RenewDeadline)*time.Second,
		time.Duration(r.config.LeaderElection.RetryPeriod)*time.Second,
		r.config.LeaderElection.ReleaseOnCancel,
	)

	return r.leaderClient, nil
}

func (r *Resolver) LoadBasicAuth(ctx context.Context, secretRef string) (*BasicAuth, error) {
	values, err := r.SecretClient().Get(ctx, secretRef)
	if err != nil {
		return nil, err
	}

	return &BasicAuth{
		Username:  values.Username,
		Password:  values.Password,
		SecretRef: secretRef,
	}, nil
}

func (r *Resolver) CoreClient(ctx context.Context) (*core.Client, error) {
	config := r.config.CoreAPI

	if config.SecretRef != "" {
		values, err := r.SecretClient().Get(ctx, r.config.CoreAPI.SecretRef)
		if err != nil {
			zap.L().Error("failed to load secret", zap.String("secretRef", config.SecretRef), zap.Error(err))
			return nil, err
		}

		config = config.FromValues(values)
	}

	options := []core.ClientOption{
		core.WithBaseURL(config.Host),
	}

	if config.Certificate != "" {
		options = append(options, core.WithCertificate(config.Certificate))
	} else if config.SkipTLS {
		options = append(options, core.WithSkipTLS())
	}

	if config.BasicAuth.Username != "" {
		options = append(options, core.WithBaseAuth(core.BasicAuth{
			Username: config.BasicAuth.Username,
			Password: config.BasicAuth.Password,
		}))
	}

	if r.config.Logging.Enabled && r.config.Logging.LogLevel < 0 {
		options = append(options, core.WithLogging())
	}

	return core.New(options)
}

func NewResolver(config *Config) Resolver {
	return Resolver{config: config}
}
