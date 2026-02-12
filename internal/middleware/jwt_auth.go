package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"foxminded/4_user_management/internal/models"
	"foxminded/4_user_management/internal/utils"
	"foxminded/4_user_management/slogger"
)

func AuthMidleware(secret string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			parts := strings.SplitN(authHeader, " ", 2)
			if !(len(parts) == 2 && parts[0] == "Bearer") {
				http.Error(w, "Invalid Authorization header", http.StatusUnauthorized)
				return
			}

			tokenString := parts[1]
			claims, err := utils.ParseToken(tokenString, secret)
			if err != nil {
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				slogger.Log.DebugContext(r.Context(), "Token parse error", "err", err)
				return
			}
			id, err := uuid.Parse(claims.UserID)
			if err != nil {
				http.Error(w, "Failed to parse user ID", http.StatusInternalServerError)
				slogger.Log.ErrorContext(r.Context(), "Failed to parse user ID", "err", err)
				return
			}
			userCtx := &models.User{
				ID:   id,
				Role: models.UserRole(claims.Role),
			}

			ctx := context.WithValue(r.Context(), UserCtxKey{}, userCtx)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
