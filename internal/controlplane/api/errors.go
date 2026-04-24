package api

import (
	"encoding/json"
	"net/http"
)

func writeJSON(rw http.ResponseWriter, status int, payload any) {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(status)
	_ = json.NewEncoder(rw).Encode(payload)
}

func writeError(rw http.ResponseWriter, status int, code, message string, reqID string) {
	writeJSON(rw, status, ErrorEnvelope{Error: ErrorModel{Code: code, Message: message, RequestID: reqID}})
}
