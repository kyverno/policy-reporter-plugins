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

	"github.com/kyverno/policy-reporter-plugins/plugins/trivy/pkg/api"
	"github.com/kyverno/policy-reporter-plugins/plugins/trivy/pkg/api/core"
	"github.com/kyverno/policy-reporter-plugins/plugins/trivy/pkg/api/cveawg"
	"github.com/kyverno/policy-reporter-plugins/plugins/trivy/pkg/api/gh"
	"github.com/kyverno/policy-reporter-plugins/plugins/trivy/pkg/kubernetes/secrets"
	"github.com/kyverno/policy-reporter-plugins/plugins/trivy/pkg/logging"
	"github.com/kyverno/policy-reporter-plugins/plugins/trivy/pkg/server"
	"github.com/kyverno/policy-reporter-plugins/plugins/trivy/pkg/vulnr"
)

type Resolver struct {
	config    *Config
	k8sConfig *rest.Config
	clientset *k8s.Clientset

	secrets secrets.Client
	db      *vulnr.Database
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

	if r.config.Logging.Server || r.config.Server.Debug {
		defaults = append(defaults, server.WithLogging(zap.L()))
	} else {
		defaults = append(defaults, server.WithRecovery())
	}

	serv := server.NewServer(engine, append(defaults, options...))

	return serv, nil
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

	options := []api.ClientOption{
		api.WithBaseURL(config.Host),
	}

	if config.Certificate != "" {
		options = append(options, api.WithCertificate(config.Certificate))
	} else if config.SkipTLS {
		options = append(options, api.WithSkipTLS())
	}

	if config.BasicAuth.Username != "" {
		options = append(options, api.WithBaseAuth(api.BasicAuth{
			Username: config.BasicAuth.Username,
			Password: config.BasicAuth.Password,
		}))
	}

	if r.config.Logging.API && r.config.Logging.LogLevel < 0 {
		options = append(options, api.WithLogging())
	}

	return core.New(options)
}

func (r *Resolver) CVEClient() (*cveawg.Client, error) {
	if r.config.Trivy.API.Disable {
		return nil, nil
	}

	options := []api.ClientOption{}

	if r.config.Logging.API && r.config.Logging.LogLevel < 0 {
		options = append(options, api.WithLogging())
	}

	return cveawg.New(options)
}

func (r *Resolver) GHClient() *gh.Client {
	if r.config.Github.Disable {
		return nil
	}

	options := []gh.ClientOption{}

	if r.config.Logging.API && r.config.Logging.LogLevel < 0 {
		options = append(options, gh.WithLogging())
	}

	return gh.New(r.config.Github.Token, options...)
}

func (r *Resolver) VulnrDB() (*vulnr.Database, error) {
	if r.db != nil {
		return r.db, nil
	}

	db, err := vulnr.NewDatabase(r.config.Trivy.DBDir)
	if err != nil {
		return nil, err
	}

	r.db = db

	return r.db, nil
}

func (r *Resolver) VulnrService() (*vulnr.Service, error) {
	cve, err := r.CVEClient()
	if err != nil {
		return nil, err
	}

	db, err := r.VulnrDB()
	if err != nil {
		return nil, err
	}

	return vulnr.New(cve, db, r.GHClient(), gocache.New(24*time.Hour, 1*time.Hour)), nil
}

func NewResolver(config *Config) Resolver {
	return Resolver{config: config}
}
