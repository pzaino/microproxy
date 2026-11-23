package dataplane

import (
	"crypto/rand"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/pzaino/microproxy/internal/dataplane/listeners"
	"github.com/pzaino/microproxy/pkg/config"
)

const (
	// maxIdempotencyEntries bounds per-provider idempotency memory.
	maxIdempotencyEntries = 512
	// idempotencyTTL bounds entry lifetime; state is process-local anyway.
	idempotencyTTL = 24 * time.Hour
	// maxIdempotencyKeyLen bounds key size to prevent memory abuse.
	maxIdempotencyKeyLen = 256
)

// SessionManager holds instance-local, provider-scoped sticky identities.
// Only providers explicitly configured with session mode username_template
// have an active dynamic identity.
type SessionManager struct {
	mu        sync.RWMutex
	states    map[string]*sessionProviderState
	randBytes func(int) ([]byte, error)
	now       func() time.Time
}

type idempotencyEntry struct {
	generation uint64
	sessionID  string
	createdAt  time.Time
}

// StaleIdempotencyKeyError reports a replay of a key that was already used for
// an older rotation. The current identity is intentionally left untouched.
type StaleIdempotencyKeyError struct {
	Provider           string
	OriginalGeneration uint64
	CurrentGeneration  uint64
}

func (e *StaleIdempotencyKeyError) Error() string {
	return fmt.Sprintf("idempotency key for provider %q was superseded: original generation %d, current generation %d", e.Provider, e.OriginalGeneration, e.CurrentGeneration)
}

type sessionProviderState struct {
	provider   string
	generation uint64
	sessionID  string
	idCfg      config.SessionIDConfig
	keys       map[string]idempotencyEntry
	keyOrder   []string
}

// NewSessionManager builds a manager and generates generation 1 for each
// session-enabled provider. On RNG failure it returns an error and no partial
// state is published for the failing provider.
func NewSessionManager(cfg *config.Config) (*SessionManager, error) {
	return NewSessionManagerWithRand(cfg, defaultRandBytes, time.Now)
}

func defaultRandBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// NewSessionManagerWithRand is the injectable constructor for tests
// (RNG failure, deterministic clock).
func NewSessionManagerWithRand(cfg *config.Config, randFn func(int) ([]byte, error), nowFn func() time.Time) (*SessionManager, error) {
	if randFn == nil {
		randFn = defaultRandBytes
	}
	if nowFn == nil {
		nowFn = time.Now
	}
	m := &SessionManager{
		states:    map[string]*sessionProviderState{},
		randBytes: randFn,
		now:       nowFn,
	}
	if cfg == nil {
		return m, nil
	}
	for _, provider := range cfg.Providers {
		name := strings.TrimSpace(provider.Name)
		if name == "" {
			continue
		}
		if !provider.Session.SessionEnabled() {
			continue
		}
		// Build the manager only from validated configs in production, but the
		// manager can also be constructed from an unvalidated config (e.g.
		// negative tests). Fail closed here so a malformed session template or
		// id generator never starts a listener with an unusable identity.
		if verr := provider.Session.Validate("providers.session", provider).OrNil(); verr != nil {
			return nil, fmt.Errorf("provider %q session config: %w", name, verr)
		}
		sessionID, err := generateSessionID(m.randBytes, provider.Session.ID)
		if err != nil {
			return nil, fmt.Errorf("provider %q initial session: %w", name, err)
		}
		m.states[name] = &sessionProviderState{
			provider:   name,
			generation: 1,
			sessionID:  sessionID,
			idCfg:      provider.Session.ID,
			keys:       map[string]idempotencyEntry{},
		}
	}
	return m, nil
}

// generateSessionID produces a per-provider sticky-session identifier using the
// provider's configured length/charset. An empty config selects the legacy
// default: 32 lowercase-hex characters (16 bytes, 128 bits of entropy).
func generateSessionID(randFn func(int) ([]byte, error), idCfg config.SessionIDConfig) (string, error) {
	return config.GenerateSessionID(randFn, idCfg)
}

// Snapshot returns the current pinned identity for a session-enabled provider.
// ok=false when the provider has no active dynamic identity.
func (m *SessionManager) Snapshot(provider string) (listeners.SessionSnapshot, bool) {
	if m == nil {
		return listeners.SessionSnapshot{}, false
	}
	name := strings.TrimSpace(provider)
	if name == "" {
		return listeners.SessionSnapshot{}, false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	state, ok := m.states[name]
	if !ok {
		return listeners.SessionSnapshot{}, false
	}
	return listeners.SessionSnapshot{Provider: name, SessionID: state.sessionID, Generation: state.generation}, true
}

// Rotate atomically advances the sticky identity for provider. The most recent
// idempotency key returns its prior generation without rotating again; a key
// from an older generation returns *StaleIdempotencyKeyError. On RNG failure
// the previous state is preserved and an error returned.
func (m *SessionManager) Rotate(provider, idempotencyKey string) (listeners.SessionSnapshot, bool, error) {
	name := strings.TrimSpace(provider)
	if name == "" {
		return listeners.SessionSnapshot{}, false, fmt.Errorf("provider cannot be empty")
	}
	if err := ValidateIdempotencyKey(idempotencyKey); err != nil {
		return listeners.SessionSnapshot{}, false, err
	}
	if m == nil {
		return listeners.SessionSnapshot{}, false, fmt.Errorf("session manager is nil")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	state, ok := m.states[name]
	if !ok {
		return listeners.SessionSnapshot{}, false, fmt.Errorf("provider %q has no active session identity", name)
	}
	now := m.now().UTC()
	m.evictExpiredLocked(state, now)
	if entry, dup := state.keys[idempotencyKey]; dup {
		if entry.generation < state.generation {
			return listeners.SessionSnapshot{}, false, &StaleIdempotencyKeyError{
				Provider:           name,
				OriginalGeneration: entry.generation,
				CurrentGeneration:  state.generation,
			}
		}
		return listeners.SessionSnapshot{Provider: name, SessionID: entry.sessionID, Generation: entry.generation}, true, nil
	}
	sessionID, err := generateSessionID(m.randBytes, state.idCfg)
	if err != nil {
		return listeners.SessionSnapshot{}, false, fmt.Errorf("generate session identity: %w", err)
	}
	if strings.TrimSpace(sessionID) == "" {
		return listeners.SessionSnapshot{}, false, fmt.Errorf("generated empty session identity")
	}
	state.generation++
	state.sessionID = sessionID
	state.keys[idempotencyKey] = idempotencyEntry{generation: state.generation, sessionID: sessionID, createdAt: now}
	state.keyOrder = append(state.keyOrder, idempotencyKey)
	// Bound memory: evict oldest beyond limit.
	for len(state.keyOrder) > maxIdempotencyEntries {
		oldest := state.keyOrder[0]
		state.keyOrder = state.keyOrder[1:]
		delete(state.keys, oldest)
	}
	return listeners.SessionSnapshot{Provider: name, SessionID: sessionID, Generation: state.generation}, false, nil
}

// Generation returns the current generation without exposing the session id.
func (m *SessionManager) Generation(provider string) (uint64, bool) {
	snapshot, ok := m.Snapshot(provider)
	if !ok {
		return 0, false
	}
	return snapshot.Generation, true
}

// Enabled reports whether a provider has an active dynamic identity.
func (m *SessionManager) Enabled(provider string) bool {
	_, ok := m.Snapshot(provider)
	return ok
}

func (m *SessionManager) evictExpiredLocked(state *sessionProviderState, now time.Time) {
	if len(state.keys) == 0 {
		return
	}
	kept := state.keyOrder[:0]
	for _, key := range state.keyOrder {
		entry, ok := state.keys[key]
		if !ok {
			continue
		}
		if now.Sub(entry.createdAt) > idempotencyTTL {
			delete(state.keys, key)
			continue
		}
		kept = append(kept, key)
	}
	state.keyOrder = kept
}

// ValidateIdempotencyKey enforces a well-formed rotation key.
func ValidateIdempotencyKey(key string) error {
	if strings.TrimSpace(key) == "" {
		return fmt.Errorf("idempotency key cannot be empty")
	}
	if len(key) > maxIdempotencyKeyLen {
		return fmt.Errorf("idempotency key too long (max %d)", maxIdempotencyKeyLen)
	}
	for _, r := range key {
		if r < 0x21 || r > 0x7e {
			return fmt.Errorf("idempotency key must be printable ASCII without spaces")
		}
		switch {
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '.' || r == ':' || r == '~' || r == '+' || r == '/' || r == '=':
		default:
			return fmt.Errorf("idempotency key contains unsupported character %q", string(r))
		}
	}
	return nil
}
