package config

import (
	"context"
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	openreportsv1alpha1 "github.com/openreports/reports-api/apis/openreports.io/v1alpha1"
	openreportsclient "github.com/openreports/reports-api/pkg/client/clientset/versioned"
	"go.uber.org/zap"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	admissionregistrationv1listers "k8s.io/client-go/listers/admissionregistration/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	"github.com/kyverno/policy-reporter/vap-plugin/pkg/builder"
	"github.com/kyverno/policy-reporter/vap-plugin/pkg/kubernetes/mapper"
	"github.com/kyverno/policy-reporter/vap-plugin/pkg/kubernetes/policy"
	"github.com/kyverno/policy-reporter/vap-plugin/pkg/kubernetes/reconcile"
	"github.com/kyverno/policy-reporter/vap-plugin/pkg/kubernetes/report"
	"github.com/kyverno/policy-reporter/vap-plugin/pkg/logging"
	"github.com/kyverno/policy-reporter/vap-plugin/pkg/server"
	apiv1 "github.com/kyverno/policy-reporter/vap-plugin/pkg/server/v1"
	"github.com/kyverno/policy-reporter/vap-plugin/pkg/webhook"
)

type Resolver struct {
	config        Config
	logger        *zap.Logger
	restConfig    *rest.Config
	reportsClient *openreportsclient.Clientset
	mapper        mapper.Mapper
	kubeClient    *kubernetes.Clientset
	dynamicClient *dynamic.DynamicClient
	vapLister     admissionregistrationv1listers.ValidatingAdmissionPolicyLister
	policyMeta    *policy.MetadataLookup
	reporter      *report.Client
	policyClient  policy.Client
}

func (r *Resolver) Logger() (*zap.Logger, error) {
	if r.logger != nil {
		return r.logger, nil
	}

	var err error
	r.logger, err = logging.New(logging.Config{Level: r.config.Logging.Level, Development: r.config.Logging.Development})
	if err != nil {
		return nil, fmt.Errorf("building logger: %w", err)
	}

	zap.ReplaceGlobals(r.logger)

	return r.logger, nil
}

func (r *Resolver) RESTConfig() (*rest.Config, error) {
	if r.restConfig != nil {
		return r.restConfig, nil
	}

	var err error
	var config *rest.Config
	if r.config.Local {
		config, err = RestConfig(r.config.Kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("building kubernetes client config: %w", err)
		}
	} else if config, err = rest.InClusterConfig(); err != nil {
		return nil, fmt.Errorf("building kubernetes client config: %w", err)
	}

	r.restConfig = config
	return r.restConfig, nil
}

func (r *Resolver) ReportsClient() (*openreportsclient.Clientset, error) {
	if r.reportsClient != nil {
		return r.reportsClient, nil
	}

	restConfig, err := r.RESTConfig()
	if err != nil {
		return nil, err
	}

	r.reportsClient, err = openreportsclient.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("building openreports client: %w", err)
	}
	return r.reportsClient, nil
}

func (r *Resolver) KubeClient() (*kubernetes.Clientset, error) {
	if r.kubeClient != nil {
		return r.kubeClient, nil
	}

	restConfig, err := r.RESTConfig()
	if err != nil {
		return nil, err
	}

	r.kubeClient, err = kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("building kubernetes client: %w", err)
	}
	return r.kubeClient, nil
}

func (r *Resolver) DynamicClient() (*dynamic.DynamicClient, error) {
	if r.dynamicClient != nil {
		return r.dynamicClient, nil
	}

	restConfig, err := r.RESTConfig()
	if err != nil {
		return nil, err
	}

	r.dynamicClient, err = dynamic.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("building dynamic client: %w", err)
	}
	return r.dynamicClient, nil
}

func (r *Resolver) VAPLister(ctx context.Context) (admissionregistrationv1listers.ValidatingAdmissionPolicyLister, error) {
	if r.vapLister != nil {
		return r.vapLister, nil
	}

	kubeClient, err := r.KubeClient()
	if err != nil {
		return nil, err
	}

	factory := informers.NewSharedInformerFactory(kubeClient, 10*time.Minute)
	informer := factory.Admissionregistration().V1().ValidatingAdmissionPolicies()

	// informer.Informer() must be called (registering it with the factory)
	// before factory.Start, or Start has nothing to start: registration
	// happens lazily on first access, not when .ValidatingAdmissionPolicies()
	// is called.
	sharedInformer := informer.Informer()
	factory.Start(ctx.Done())

	syncCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if !cache.WaitForCacheSync(syncCtx.Done(), sharedInformer.HasSynced) {
		return nil, fmt.Errorf("syncing ValidatingAdmissionPolicy informer cache: %w", syncCtx.Err())
	}

	r.vapLister = informer.Lister()
	return r.vapLister, nil
}

func (r *Resolver) PolicyMetadataLookup(ctx context.Context) (*policy.MetadataLookup, error) {
	if r.policyMeta != nil {
		return r.policyMeta, nil
	}

	vapLister, err := r.VAPLister(ctx)
	if err != nil {
		return nil, err
	}

	r.policyMeta = policy.NewMetadataLookup(vapLister)
	return r.policyMeta, nil
}

func (r *Resolver) Reporter(ctx context.Context) (*report.Client, error) {
	if r.reporter != nil {
		return r.reporter, nil
	}

	reportsClient, err := r.ReportsClient()
	if err != nil {
		return nil, err
	}

	restMapper, err := r.Mapper()
	if err != nil {
		return nil, err
	}

	dynamicClient, err := r.DynamicClient()
	if err != nil {
		return nil, err
	}

	policyMeta, err := r.PolicyMetadataLookup(ctx)
	if err != nil {
		return nil, err
	}

	r.reporter = report.New(reportsClient, restMapper, dynamicClient, policyMeta, r.config.Report.Labels, r.config.Report.Annotations, builder.Options{
		Severity: openreportsv1alpha1.ResultSeverity(r.config.Report.Severity),
		Category: r.config.Report.Category,
	})
	return r.reporter, nil
}

func (r *Resolver) PolicyClient(ctx context.Context) (policy.Client, error) {
	if r.policyClient != nil {
		return r.policyClient, nil
	}

	lister, err := r.VAPLister(ctx)
	if err != nil {
		return nil, err
	}

	r.policyClient = policy.NewClient(lister, policy.Defaults{
		Severity: r.config.Report.Severity,
		Category: r.config.Report.Category,
	})
	return r.policyClient, nil
}

func (r *Resolver) Mapper() (mapper.Mapper, error) {
	if r.mapper != nil {
		return r.mapper, nil
	}

	restConfig, err := r.RESTConfig()
	if err != nil {
		return nil, err
	}

	discoveryClient, err := discovery.NewDiscoveryClientForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("building discovery client: %w", err)
	}
	r.mapper = mapper.New(discoveryClient)
	return r.mapper, nil
}

func (r *Resolver) WebhookServer(ctx context.Context) (*webhook.Server, error) {
	logger, err := r.Logger()
	if err != nil {
		return nil, err
	}

	reporter, err := r.Reporter(ctx)
	if err != nil {
		return nil, err
	}
	return webhook.NewServer(reporter, logger, r.config.Webhook.BufferSize, r.config.Report.ReportDenied), nil
}

func (r *Resolver) APIServer(ctx context.Context) (*server.Server, error) {
	if !r.config.API.Debug {
		gin.SetMode(gin.ReleaseMode)
	}

	policyClient, err := r.PolicyClient(ctx)
	if err != nil {
		return nil, err
	}

	options := []server.ServerOption{
		server.WithGZIP(),
		server.WithRecovery(),
		apiv1.WithAPI(policyClient),
		server.WithPort(r.config.API.Port),
	}

	if r.config.API.Auth.Username != "" && r.config.API.Auth.Password != "" {
		options = append(options, server.WithBasicAuth(server.BasicAuth{
			Username: r.config.API.Auth.Username,
			Password: r.config.API.Auth.Password,
		}))
	}

	return server.NewServer(gin.New(), options), nil
}

func (r *Resolver) Sweeper() (*reconcile.Sweeper, error) {
	logger, err := r.Logger()
	if err != nil {
		return nil, err
	}

	reportsClient, err := r.ReportsClient()
	if err != nil {
		return nil, err
	}

	return reconcile.NewSweeper(reportsClient, r.config.Report.Labels, r.config.Report.Annotations, r.config.Reconcile.OrphanTTL, logger), nil
}

func (r *Resolver) Config() Config {
	return r.config
}

func NewResolver(config Config) *Resolver {
	return &Resolver{
		config: config,
	}
}
