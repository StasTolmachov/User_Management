package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"foxminded/4_user_management/internal/models"
	"foxminded/4_user_management/slogger"
)

func TestMain(m *testing.M) {
	slogger.MakeLogger(true)
	os.Exit(m.Run())
}
func TestBasicAuthMiddleware(t *testing.T) {
	testUser := &models.User{ID: uuid.New(), Email: "test@example.com"}

	tests := []struct {
		name           string
		username       string
		password       string
		authFuncResult *models.User
		authFuncErr    error
		expectedStatus int
	}{
		{
			name:           "Success: Valid Credentials",
			username:       "test@example.com",
			password:       "password",
			authFuncResult: testUser,
			authFuncErr:    nil,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Failure: No Credentials",
			username:       "",
			password:       "",
			authFuncResult: nil,
			authFuncErr:    nil,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Failure: Invalid Credentials (AuthFunc returns error)",
			username:       "wrong",
			password:       "pass",
			authFuncResult: nil,
			authFuncErr:    errors.New("invalid credentials"),
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mockAuthFunc := func(ctx context.Context, email, pass string) (*models.User, error) {
				return tt.authFuncResult, tt.authFuncErr
			}

			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				userCtx := r.Context().Value(UserCtxKey{})
				if tt.expectedStatus == http.StatusOK {
					assert.NotNil(t, userCtx, "User should be in context")
					assert.Equal(t, testUser, userCtx)
				}
				w.WriteHeader(http.StatusOK)
			})

			handler := BasicAuthMiddleware(mockAuthFunc)(nextHandler)

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.username != "" || tt.password != "" {
				req.SetBasicAuth(tt.username, tt.password)
			}
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)
		})
	}
}
