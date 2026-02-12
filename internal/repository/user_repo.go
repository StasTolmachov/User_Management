package repository

import (
	"context"
	"time"

	"github.com/google/uuid"

	"foxminded/4_user_management/internal/repository/models"
)

type UserRepository interface {
	Create(ctx context.Context, req *models.UserDB) (*models.UserDB, error)
	GetPasswordHashByEmail(ctx context.Context, email string) (*models.UserDB, error)
	GetUserByID(ctx context.Context, id uuid.UUID) (*models.UserDB, error)
	Delete(ctx context.Context, id uuid.UUID) error
	Update(ctx context.Context, id uuid.UUID, fields map[string]any) (*models.UserDB, error)
	GetUsers(ctx context.Context, order string, pagination models.Pagination) ([]models.UserDB, uint64, error)
	Vote(ctx context.Context, userID, targetID uuid.UUID, value int) error
	GetLastVoteTime(ctx context.Context, userID uuid.UUID) (time.Time, error)
}
