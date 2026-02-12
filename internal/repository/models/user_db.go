package models

import (
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

type UserDB struct {
	ID           uuid.UUID  `db:"id"`
	Email        string     `db:"email"`
	PasswordHash string     `db:"password_hash"`
	FirstName    string     `db:"first_name"`
	LastName     string     `db:"last_name"`
	Role         string     `db:"role"`
	Rating       int        `db:"rating"`
	CreatedAt    time.Time  `db:"created_at"`
	UpdatedAt    time.Time  `db:"updated_at"`
	DeletedAt    *time.Time `db:"deleted_at"`
}

var (
	ErrDuplicateEmail = errors.New("duplicate email")
	ErrUserNotFound   = errors.New("user not found")
)

func ParseDBError(err error) error {
	if err == nil {
		return nil
	}

	if strings.Contains(err.Error(), "duplicate key value violates unique constraint") {
		return ErrDuplicateEmail
	}

	return err
}

type UserDBWithTotal struct {
	UserDB
	Total uint64 `json:"total"`
}

type Pagination struct {
	Limit  uint64
	Offset uint64
}
