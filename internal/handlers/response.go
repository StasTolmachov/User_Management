package handlers

import (
	"encoding/json"
	"net/http"
)

type JSONError struct {
	Error string `json:"error"`
}

func JSONResponse(w http.ResponseWriter, statusCode int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(payload); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}
func WriteError(w http.ResponseWriter, code int, message string) {
	JSONResponse(w, code, JSONError{Error: message})
}
