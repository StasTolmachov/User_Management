package models

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"foxminded/4_user_management/internal/repository/models"
)

func TestNewUser(t *testing.T) {
	tests := []struct {
		name    string
		req     CreateUserRequest
		role    UserRole
		wantErr bool
	}{
		{
			name: "Success",
			req: CreateUserRequest{
				Email:     "test@example.com",
				Password:  "StrongPass1!",
				FirstName: "John",
				LastName:  "Doe",
			},
			role:    RoleUser,
			wantErr: false,
		},
		{
			name: "Empty Email",
			req: CreateUserRequest{
				Email:     "",
				Password:  "StrongPass1!",
				FirstName: "John",
				LastName:  "Doe",
			},
			role:    RoleUser,
			wantErr: true,
		},
		{
			name: "Empty Password",
			req: CreateUserRequest{
				Email:     "test@example.com",
				Password:  "",
				FirstName: "John",
				LastName:  "Doe",
			},
			role:    RoleUser,
			wantErr: true,
		},
		{
			name: "Create Admin User Successfully",
			req: CreateUserRequest{
				Email:     "admin@admin.com",
				Password:  "StrongPass1!",
				FirstName: "Admin",
				LastName:  "Admin",
			},
			role:    RoleAdmin,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			user, err := NewUser(tt.req, tt.role)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, user)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, user)
				assert.NotEmpty(t, user.ID)
				assert.NotEqual(t, tt.req.Password, user.PasswordHash)
				assert.Equal(t, tt.role, user.Role)
			}
		})
	}
}

func TestMappers(t *testing.T) {
	id := uuid.New()
	now := time.Now()

	domainUser := &User{
		ID:           id,
		Email:        "test@example.com",
		PasswordHash: "hash",
		FirstName:    "John",
		LastName:     "Doe",
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	dbUser := &models.UserDB{
		ID:           id,
		Email:        "test@example.com",
		PasswordHash: "hash",
		FirstName:    "John",
		LastName:     "Doe",
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	t.Run("ToUserResponse", func(t *testing.T) {
		resp := ToUserResponse(domainUser)
		assert.Equal(t, domainUser.ID.String(), resp.ID)
		assert.Equal(t, domainUser.Email, resp.Email)
		assert.Equal(t, domainUser.CreatedAt.String(), resp.CreatedAt)
	})

	t.Run("ToUserDB", func(t *testing.T) {
		resDB := ToUserDB(domainUser)
		assert.Equal(t, domainUser.ID, resDB.ID)
		assert.Equal(t, domainUser.Email, resDB.Email)
		assert.Equal(t, domainUser.PasswordHash, resDB.PasswordHash)
	})

	t.Run("FromUserDB", func(t *testing.T) {
		resDomain := FromUserDB(dbUser)
		assert.Equal(t, dbUser.ID, resDomain.ID)
		assert.Equal(t, dbUser.Email, resDomain.Email)
	})

	t.Run("FromDBToUserResponse", func(t *testing.T) {
		resp := FromDBToUserResponse(dbUser)
		assert.Equal(t, dbUser.ID.String(), resp.ID)
		assert.Equal(t, dbUser.Email, resp.Email)
	})
}
