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
	if s.ghClient != nil && strings.HasPrefix(name, "GHSA") {
		ghsa, err := s.ghClient.Get(ctx, name)
		if err != nil {
			return nil, err
		}

		details = MapSecurityAdvisory(ghsa)
	} else if s.cveAPI != nil {
		cve, err := s.cveAPI.GetCVE(ctx, name)
		if err != nil {
			return nil, err
		}

		trivyCVE, err := s.db.Get(name)
		if err != nil {
			zap.L().Warn("unable to load CVE from TrivyDB", zap.String("cve", name), zap.Error(err))
		}

		details = MapCVE(cve, trivyCVE)
	} else {
		trivyCVE, err := s.db.Get(name)
		if err != nil {
			zap.L().Warn("unable to load CVE from TrivyDB", zap.String("cve", name), zap.Error(err))
			return &Vulnerability{ID: name, Title: name}, nil
		}

		details = MapFromTrivyDB(name, trivyCVE)
	}

	s.cache.Set(name, details, gocache.DefaultExpiration)

	return details, nil
}

func (s *Service) GetDescription(ctx context.Context, name string) (*Vulnerability, error) {
	if cached, ok := s.cache.Get("list/" + name); ok {
		return cached.(*Vulnerability), nil
	}

	if s.ghClient != nil && strings.HasPrefix(name, "GHSA") {
		ghsa, err := s.ghClient.Get(ctx, name)
		if err != nil {
			return nil, err
		}

		zap.L().Debug("got vulnr details from github api", zap.String("cve", name))
		details := MapSecurityAdvisory(ghsa)
		s.cache.Set("list/"+name, details, gocache.DefaultExpiration)

		return details, nil
	}

	if trivyCVE, err := s.db.Get(name); trivyCVE != nil {
		details := MapFromTrivyDB(name, trivyCVE)
		s.cache.Set("list/"+name, details, gocache.DefaultExpiration)
		zap.L().Debug("got vulnr details from trivy db, skip api call", zap.String("cve", name))

		return details, nil
	} else {
		zap.L().Warn("unable to load CVE from TrivyDB", zap.String("cve", name), zap.Error(err))
	}

	if s.cveAPI == nil {
		return &Vulnerability{
			ID:    name,
			Title: name,
		}, nil
	}

	cve, err := s.cveAPI.GetCVE(ctx, name)
	if err != nil {
		zap.L().Error("unable to load CVE from CVEAWG API", zap.String("cve", name), zap.Error(err))
		return nil, err
	}

	zap.L().Debug("got vulnr details from CVEAWG API", zap.String("cve", name))
	details := MapFromAPI(name, cve)
	s.cache.Set("list/"+name, details, gocache.DefaultExpiration)

	return details, nil
}

func New(cveAPI *cveawg.Client, db *Database, ghClient *gh.Client, cache *gocache.Cache) *Service {
	return &Service{cveAPI, db, ghClient, cache}
}
