package middleware

import (
	"context"
	"net/http"

	"foxminded/4_user_management/internal/models"
	"foxminded/4_user_management/slogger"
)

type UserCtxKey struct{}

func BasicAuthMiddleware(authFunc func(ctx context.Context, email, pass string) (*models.User, error)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			email, pass, ok := r.BasicAuth()
			if !ok {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			user, err := authFunc(r.Context(), email, pass)
			slogger.Log.DebugContext(r.Context(), "BasicAuthMiddleware", "email", email, "user", user)
			if err != nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			ctx := context.WithValue(r.Context(), UserCtxKey{}, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
