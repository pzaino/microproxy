package api

import (
	"errors"
	"sort"
	"strconv"
	"sync"
)

var (
	ErrProviderNotFound = errors.New("provider not found")
	ErrProviderExists   = errors.New("provider already exists")
	ErrVersionConflict  = errors.New("resource version conflict")
	ErrValidationFailed = errors.New("validation failed")
)

type ProviderStateStore interface {
	ListProviders() []Provider
	GetProvider(id string) (Provider, bool)
	CreateProvider(provider ProviderSpec) (Provider, error)
	ReplaceProvider(id, expectedVersion string, provider ProviderSpec) (Provider, error)
	PatchProvider(id, expectedVersion string, patch map[string]any) (Provider, error)
	DeleteProvider(id, expectedVersion string) error
}

type inMemoryProviderStore struct {
	mu        sync.RWMutex
	providers map[string]Provider
}

func NewInMemoryProviderStore() ProviderStateStore {
	return &inMemoryProviderStore{providers: map[string]Provider{}}
}

func (s *inMemoryProviderStore) ListProviders() []Provider {
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]Provider, 0, len(s.providers))
	for _, provider := range s.providers {
		items = append(items, provider)
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].ID < items[j].ID
	})
	return items
}

func (s *inMemoryProviderStore) GetProvider(id string) (Provider, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	provider, ok := s.providers[id]
	return provider, ok
}

func (s *inMemoryProviderStore) CreateProvider(spec ProviderSpec) (Provider, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.providers[spec.ID]; exists {
		return Provider{}, ErrProviderExists
	}

	provider := Provider{ID: spec.ID, ResourceVersion: "1", Spec: spec}
	s.providers[spec.ID] = provider
	return provider, nil
}

func (s *inMemoryProviderStore) ReplaceProvider(id, expectedVersion string, spec ProviderSpec) (Provider, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	current, exists := s.providers[id]
	if !exists {
		return Provider{}, ErrProviderNotFound
	}
	if expectedVersion != current.ResourceVersion {
		return Provider{}, ErrVersionConflict
	}

	next, err := incrementVersion(current.ResourceVersion)
	if err != nil {
		return Provider{}, err
	}

	provider := Provider{ID: id, ResourceVersion: next, Spec: spec}
	s.providers[id] = provider
	return provider, nil
}

func (s *inMemoryProviderStore) PatchProvider(id, expectedVersion string, patch map[string]any) (Provider, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	current, exists := s.providers[id]
	if !exists {
		return Provider{}, ErrProviderNotFound
	}
	if expectedVersion != current.ResourceVersion {
		return Provider{}, ErrVersionConflict
	}

	next, err := incrementVersion(current.ResourceVersion)
	if err != nil {
		return Provider{}, err
	}

	nextSpec := current.Spec
	if nameRaw, ok := patch["name"]; ok {
		nextSpec.Name = nameRaw.(string)
	}
	if typeRaw, ok := patch["type"]; ok {
		nextSpec.Type = typeRaw.(string)
	}
	if endpointRaw, ok := patch["endpoint"]; ok {
		nextSpec.Endpoint = endpointRaw.(string)
	}

	provider := Provider{ID: id, ResourceVersion: next, Spec: nextSpec}
	s.providers[id] = provider
	return provider, nil
}

func (s *inMemoryProviderStore) DeleteProvider(id, expectedVersion string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	current, exists := s.providers[id]
	if !exists {
		return ErrProviderNotFound
	}
	if expectedVersion != current.ResourceVersion {
		return ErrVersionConflict
	}

	delete(s.providers, id)
	return nil
}

func incrementVersion(version string) (string, error) {
	v, err := strconv.ParseUint(version, 10, 64)
	if err != nil {
		return "", err
	}
	return strconv.FormatUint(v+1, 10), nil
}
