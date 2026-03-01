package handlers

import (
	"net/http"

	"github.com/iim-protocol/iimp/server/auth"
	"github.com/iim-protocol/iimp/server/logger"
)

func GetJWKSStore(w http.ResponseWriter, r *http.Request) {
	// Return the JWK Set as JSON
	response, err := auth.JWKSet.JSONPublic(r.Context())
	if err != nil {
		logger.Error.Println("error getting JWKS JSON:", err)
		http.Error(w, "error getting JWKS JSON", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(response)
}
