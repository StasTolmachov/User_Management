package models

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"foxminded/4_user_management/internal/repository/models"
	"foxminded/4_user_management/internal/utils"
)

type User struct {
	ID           uuid.UUID
	Email        string
	PasswordHash string
	FirstName    string
	LastName     string
	Role         UserRole
	CreatedAt    time.Time
	UpdatedAt    time.Time
	DeletedAt    *time.Time
}

// NewUser creates a new User instance from the provided CreateUserRequest, validating required fields and hashing the password.
func NewUser(req CreateUserRequest, role UserRole) (*User, error) {
	if req.Email == "" || req.Password == "" || req.FirstName == "" || req.LastName == "" {
		return nil, fmt.Errorf("cannot create user with empty fields")
	}
	err := utils.ValidatePassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("invalid password: %w", err)
	}

	hash, err := utils.HashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("cannot hash password: %w", err)
	}

	id := uuid.New()

	timeNow := time.Now()

	return &User{
		ID:           id,
		Email:        req.Email,
		PasswordHash: hash,
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		Role:         role,
		CreatedAt:    timeNow,
		UpdatedAt:    timeNow,
		DeletedAt:    nil,
	}, nil
}

// ToUserResponse converts a User domain object into a UserResponse DTO for external use.
func ToUserResponse(user *User) *UserResponse {
	return &UserResponse{
		ID:        user.ID.String(),
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Role:      string(user.Role),
		CreatedAt: user.CreatedAt.String(),
		UpdatedAt: user.UpdatedAt.String(),
	}
}

// FromUserDB converts a UserDB data model to a User domain object.
func FromUserDB(user *models.UserDB) *User {
	return &User{
		ID:           user.ID,
		Email:        user.Email,
		PasswordHash: user.PasswordHash,
		FirstName:    user.FirstName,
		LastName:     user.LastName,
		Role:         UserRole(user.Role),
		CreatedAt:    user.CreatedAt,
		UpdatedAt:    user.UpdatedAt,
	}
}
func ToUserDB(user *User) *models.UserDB {
	return &models.UserDB{
		ID:           user.ID,
		Email:        user.Email,
		PasswordHash: user.PasswordHash,
		FirstName:    user.FirstName,
		LastName:     user.LastName,
		Role:         string(user.Role),
		CreatedAt:    user.CreatedAt,
		UpdatedAt:    user.UpdatedAt,
		DeletedAt:    user.DeletedAt,
	}
}

// CreateUserRequest represents a request payload for creating a new user with required fields and validation rules.
type CreateUserRequest struct {
	Email     string `json:"email" validate:"required,email" example:"test@user.com"`
	Password  string `json:"password" validate:"required,min=8" example:"SecurePass123!"`
	FirstName string `json:"first_name" validate:"required" example:"test"`
	LastName  string `json:"last_name" validate:"required" example:"user"`
}

// UpdateUserRequest represents a request to update a user's information, with optional fields for partial updates.
type UpdateUserRequest struct {
	Email     *string `json:"email,omitempty"`
	Password  *string `json:"password,omitempty"`
	FirstName *string `json:"first_name,omitempty"`
	LastName  *string `json:"last_name,omitempty"`
	Role      *string `json:"role,omitempty"`
}

type UserResponse struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Role      string `json:"role"`
	Rating    int    `json:"rating"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

func FromDBToUserResponse(user *models.UserDB) *UserResponse {
	return &UserResponse{
		ID:        user.ID.String(),
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Role:      user.Role,
		Rating:    user.Rating,
		CreatedAt: user.CreatedAt.String(),
		UpdatedAt: user.UpdatedAt.String(),
	}
}

type ListOfUsersResponse struct {
	Page  uint64          `json:"page"`
	Limit uint64          `json:"limit"`
	Total uint64          `json:"total"`
	Pages uint64          `json:"pages"`
	Data  []*UserResponse `json:"data"`
}

var (
	ErrUserAlreadyExists  = errors.New("user already exists")
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrPermissionDenied   = errors.New("permission denied")

	ErrSelfVoting   = errors.New("users cannot vote for themselves")
	ErrVoteTooOften = errors.New("you can vote only once per minute")
)

type UserRole string

const (
	RoleUser      UserRole = "user"
	RoleModerator UserRole = "moderator"
	RoleAdmin     UserRole = "admin"
)

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email" example:"test@user.com"`
	Password string `json:"password" validate:"required" example:"SecurePass123!"`
}

type LoginResponse struct {
	Token string `json:"token"`
}

type VoteRequest struct {
	TargetID uuid.UUID `json:"-"`
	Value    int       `json:"value" validate:"oneof=-1 0 1"`
}
