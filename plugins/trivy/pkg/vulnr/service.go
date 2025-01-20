package vulnr

import (
	"context"
	"strings"

	gocache "github.com/patrickmn/go-cache"
	"go.uber.org/zap"

	"github.com/kyverno/policy-reporter-plugins/plugins/trivy/pkg/api/cveawg"
	"github.com/kyverno/policy-reporter-plugins/plugins/trivy/pkg/api/gh"
)

type Service struct {
	cveAPI   *cveawg.Client
	db       *Database
	ghClient *gh.Client
	cache    *gocache.Cache
}

func (s *Service) Get(ctx context.Context, name string) (*Vulnerability, error) {
	if cached, ok := s.cache.Get(name); ok {
		return cached.(*Vulnerability), nil
	}

	var details *Vulnerability
	if strings.HasPrefix(name, "GHSA") {
		ghsa, err := s.ghClient.Get(ctx, name)
		if err != nil {
			return nil, err
		}

		details = MapSecurityAdvisory(ghsa)
	} else {
		cve, err := s.cveAPI.GetCVE(ctx, name)
		if err != nil {
			return nil, err
		}

		trivyCVE, err := s.db.Get(name)
		if err != nil {
			zap.L().Warn("unable to load CVE from TrivyDB", zap.String("cve", name), zap.Error(err))
		}

		details = MapCVE(cve, trivyCVE)
	}

	s.cache.Set(name, details, gocache.DefaultExpiration)

	return details, nil
}

func New(cveAPI *cveawg.Client, db *Database, ghClient *gh.Client, cache *gocache.Cache) *Service {
	return &Service{cveAPI, db, ghClient, cache}
}
