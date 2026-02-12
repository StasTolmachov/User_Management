package utils

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"foxminded/4_user_management/internal/config"
)

func TestJWT(t *testing.T) {
	userID := uuid.New()
	role := "admin"

	jwt := config.JWT{Secret: "super-secret-key", TTL: time.Hour}

	t.Run("Generate and Parse Token", func(t *testing.T) {
		tokenString, err := GenerateToken(userID, role, jwt)
		assert.NoError(t, err)
		assert.NotEmpty(t, tokenString)

		claims, err := ParseToken(tokenString, jwt.Secret)
		assert.NoError(t, err)
		assert.NotNil(t, claims)

		assert.Equal(t, userID.String(), claims.UserID)
		assert.Equal(t, role, claims.Role)
	})

	t.Run("Parse Invalid Token (Wrong Secret)", func(t *testing.T) {
		tokenString, _ := GenerateToken(userID, role, jwt)

		_, err := ParseToken(tokenString, "wrong-secret")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "signature is invalid")
	})

	t.Run("Parse Expired Token", func(t *testing.T) {
		jwt.TTL = -1 * time.Hour
		tokenString, _ := GenerateToken(userID, role, jwt)

		_, err := ParseToken(tokenString, jwt.Secret)
		assert.Error(t, err)
	})
}
