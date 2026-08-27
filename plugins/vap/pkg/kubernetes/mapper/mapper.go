// Package mapper resolves a GroupVersionResource (all an audit event's
// ObjectRef carries) to a GroupVersionKind (needed to populate a Report's
// Scope and OwnerReference, which both require Kind).
package mapper

import (
	"fmt"
	"sync"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/restmapper"
)

// Mapper resolves resource identity to kind.
type Mapper interface {
	KindFor(gvr schema.GroupVersionResource) (schema.GroupVersionKind, error)
}

// discoveryMapper is a RESTMapper backed by cluster discovery, refreshed
// on cache miss so newly installed CRDs become resolvable without a
// restart. Discovery calls are not on the audit-event hot path in the
// common case: only a cache miss (a resource kind not seen before) pays for
// one.
type discoveryMapper struct {
	dc discovery.DiscoveryInterface

	mu       sync.RWMutex
	delegate meta.RESTMapper
}

// New returns a Mapper backed by the given discovery client.
func New(dc discovery.DiscoveryInterface) Mapper {
	return &discoveryMapper{dc: dc}
}

func (m *discoveryMapper) KindFor(gvr schema.GroupVersionResource) (schema.GroupVersionKind, error) {
	if kind, ok := m.lookup(gvr); ok {
		return kind, nil
	}

	if err := m.refresh(); err != nil {
		return schema.GroupVersionKind{}, fmt.Errorf("refreshing REST mapper: %w", err)
	}

	if kind, ok := m.lookup(gvr); ok {
		return kind, nil
	}

	return schema.GroupVersionKind{}, fmt.Errorf("no kind registered for resource %s", gvr.String())
}

func (m *discoveryMapper) lookup(gvr schema.GroupVersionResource) (schema.GroupVersionKind, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.delegate == nil {
		return schema.GroupVersionKind{}, false
	}

	kind, err := m.delegate.KindFor(gvr)
	if err != nil {
		return schema.GroupVersionKind{}, false
	}

	return kind, true
}

func (m *discoveryMapper) refresh() error {
	groupResources, err := restmapper.GetAPIGroupResources(m.dc)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.delegate = restmapper.NewDiscoveryRESTMapper(groupResources)

	return nil
}
