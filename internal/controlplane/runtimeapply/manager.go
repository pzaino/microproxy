package runtimeapply

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"

	"github.com/pzaino/microproxy/internal/dataplane"
	"github.com/pzaino/microproxy/internal/dataplane/policy"
	"github.com/pzaino/microproxy/pkg/config"
)

type Op string

const (
	OpCreateProvider Op = "create_provider"
	OpReplaceProvider Op = "replace_provider"
	OpPatchProvider   Op = "patch_provider"
	OpDeleteProvider  Op = "delete_provider"
)

type ProviderMutation struct {
	Op              Op
	ProviderID      string
	ExpectedVersion string
	Spec            ProviderSpec
	Patch           map[string]any
}

type ProviderSpec struct{ ID, Name, Type, Endpoint string }
type Provider struct{ ID, ResourceVersion string; Spec ProviderSpec }

type ProviderStore interface {
	ListProviders() []Provider
	CreateProvider(ProviderSpec) (Provider, error)
	ReplaceProvider(id, expectedVersion string, provider ProviderSpec) (Provider, error)
	PatchProvider(id, expectedVersion string, patch map[string]any) (Provider, error)
	DeleteProvider(id, expectedVersion string) error
}

type RuntimeComponents struct {
	Resolver         **dataplane.RouteResolver
	ProviderRegistry **dataplane.ProviderRegistry
	PolicyEngine     **policy.Engine
}

type Manager struct {
	mu sync.Mutex

	cfg             *config.Config
	store           ProviderStore
	components      RuntimeComponents
	resourceVersion uint64
	onReject        func(requestID string, version uint64, err error)
	onApplied       func(requestID string, prev, next uint64)
}

func New(cfg *config.Config, store ProviderStore, components RuntimeComponents) *Manager {
	return &Manager{cfg: cfg, store: store, components: components, resourceVersion: 1}
}

func (m *Manager) SetEventHooks(applied func(string, uint64, uint64), reject func(string, uint64, error)) {
	m.onApplied = applied
	m.onReject = reject
}

func (m *Manager) ApplyProviderMutation(requestID string, mutation ProviderMutation) (Provider, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	prevCfg := cloneConfig(m.cfg)
	prevResolver, prevRegistry, prevPolicy := *m.components.Resolver, *m.components.ProviderRegistry, *m.components.PolicyEngine
	before := m.resourceVersion

	applyCfgMutation(m.cfg, mutation)
	if err := validateCrossResourceReferences(m.cfg); err != nil {
		m.cfg = prevCfg
		m.reject(requestID, before, err)
		return Provider{}, err
	}

	var result Provider
	var err error
	switch mutation.Op {
	case OpCreateProvider:
		result, err = m.store.CreateProvider(mutation.Spec)
	case OpReplaceProvider:
		result, err = m.store.ReplaceProvider(mutation.ProviderID, mutation.ExpectedVersion, mutation.Spec)
	case OpPatchProvider:
		result, err = m.store.PatchProvider(mutation.ProviderID, mutation.ExpectedVersion, mutation.Patch)
	case OpDeleteProvider:
		err = m.store.DeleteProvider(mutation.ProviderID, mutation.ExpectedVersion)
	default:
		err = fmt.Errorf("unsupported op %q", mutation.Op)
	}
	if err != nil {
		m.cfg = prevCfg
		m.reject(requestID, before, err)
		return Provider{}, err
	}

	if err := m.rebuildRuntimeComponents(); err != nil {
		m.cfg = prevCfg
		*m.components.Resolver, *m.components.ProviderRegistry, *m.components.PolicyEngine = prevResolver, prevRegistry, prevPolicy
		m.reject(requestID, before, err)
		return Provider{}, err
	}
	m.resourceVersion++
	m.applied(requestID, before, m.resourceVersion)
	return result, nil
}

func cloneConfig(cfg *config.Config) *config.Config {
	data, _ := json.Marshal(cfg)
	cloned := config.NewConfig()
	_ = json.Unmarshal(data, cloned)
	return cloned
}

func (m *Manager) applied(requestID string, prev, next uint64) {
	slog.Info("config.applied", "request_id", requestID, "version_before", prev, "version_after", next)
	if m.onApplied != nil {
		m.onApplied(requestID, prev, next)
	}
}

func (m *Manager) reject(requestID string, v uint64, err error) {
	slog.Warn("config.rejected", "request_id", requestID, "version", v, "error", err.Error())
	if m.onReject != nil {
		m.onReject(requestID, v, err)
	}
}

func (m *Manager) rebuildRuntimeComponents() error {
	if strings.TrimSpace(m.cfg.Observability.AccessLog.Format) == "force-runtime-fail" {
		return fmt.Errorf("forced runtime component failure")
	}
	*m.components.Resolver = dataplane.NewRouteResolver(m.cfg)
	*m.components.ProviderRegistry = dataplane.NewProviderRegistry(m.cfg)
	*m.components.PolicyEngine = policy.NewEngine(m.cfg)
	return nil
}

func validateCrossResourceReferences(cfg *config.Config) error {
	providerSet := map[string]struct{}{}
	policySet := map[string]struct{}{}
	for _, p := range cfg.Providers {
		providerSet[p.Name] = struct{}{}
	}
	for _, p := range cfg.Policies {
		policySet[p.Name] = struct{}{}
	}
	for i, t := range cfg.Tenants {
		for _, p := range t.Providers {
			if _, ok := providerSet[p]; !ok {
				return fmt.Errorf("tenants[%d].providers references unknown provider %q", i, p)
			}
		}
		for _, p := range t.Policies {
			if _, ok := policySet[p]; !ok {
				return fmt.Errorf("tenants[%d].policies references unknown policy %q", i, p)
			}
		}
	}
	if p := strings.TrimSpace(cfg.Routing.DefaultProvider); p != "" {
		if _, ok := providerSet[p]; !ok {
			return fmt.Errorf("routing.default_provider must reference an existing provider name")
		}
	}
	for i, r := range cfg.Routing.Rules {
		if _, ok := providerSet[r.Provider]; !ok {
			return fmt.Errorf("routing.rules[%d].provider must reference an existing provider name", i)
		}
		if policy := strings.TrimSpace(r.PolicyRef); policy != "" {
			if _, ok := policySet[policy]; !ok {
				return fmt.Errorf("routing.rules[%d].policy_ref must reference an existing policy name", i)
			}
		}
	}
	return nil
}

func ParseIfMatchVersion(value string) string {
	value = strings.TrimSpace(strings.Trim(value, "\""))
	if value == "" {
		return ""
	}
	if _, err := strconv.ParseUint(value, 10, 64); err != nil {
		return ""
	}
	return value
}

func applyCfgMutation(cfg *config.Config, mutation ProviderMutation) {
	providers := make([]config.ProviderConfig, 0, len(cfg.Providers))
	current := config.ProviderConfig{}
	for _, p := range cfg.Providers {
		if p.Name == mutation.ProviderID {
			current = p
		}
		if p.Name != mutation.ProviderID {
			providers = append(providers, p)
		}
	}
	if mutation.Op != OpDeleteProvider {
		spec := mutation.Spec
		if mutation.Op == OpPatchProvider {
			spec = ProviderSpec{ID: mutation.ProviderID, Name: current.Name, Type: current.Type}
			if len(current.Endpoints) > 0 {
				spec.Endpoint = current.Endpoints[0].URL
			}
			if v, ok := mutation.Patch["name"].(string); ok { spec.Name = v }
			if v, ok := mutation.Patch["type"].(string); ok { spec.Type = v }
			if v, ok := mutation.Patch["endpoint"].(string); ok { spec.Endpoint = v }
		}
		providers = append(providers, config.ProviderConfig{Name: spec.ID, Type: spec.Type, Endpoints: []config.ProviderEndpoint{{URL: spec.Endpoint}}})
	}
	cfg.Providers = providers
}
