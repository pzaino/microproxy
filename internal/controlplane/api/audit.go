package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

type auditRecord struct {
	Actor     actorIdentity `json:"actor"`
	Timestamp time.Time     `json:"timestamp"`
	RequestID string        `json:"request_id"`
	Action    string        `json:"action"`
	Before    string        `json:"before_hash"`
	After     string        `json:"after_hash"`
	Result    string        `json:"result"`
}

type auditLog struct { mu sync.Mutex; records []auditRecord }

func (a *auditLog) append(rec auditRecord) {
	a.mu.Lock(); defer a.mu.Unlock()
	a.records = append(a.records, rec)
	slog.Info("control-plane audit", "actor", rec.Actor.ID, "role", rec.Actor.Role, "request_id", rec.RequestID, "action", rec.Action, "before_hash", rec.Before, "after_hash", rec.After, "result", rec.Result)
}

func hashAny(v any) string {
	if v == nil { return "" }
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func actorFromRequest(req *http.Request) actorIdentity {
	if req == nil { return actorIdentity{} }
	if v, ok := req.Context().Value(actorContextKey).(actorIdentity); ok { return v }
	return actorIdentity{}
}
