package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"foxminded/4_user_management/internal/repository/models"
)

type UserRepo struct {
	db *Postgres
}

var allowedUpdateColumns = map[string]bool{
	"email":         true,
	"password_hash": true,
	"first_name":    true,
	"last_name":     true,
	"role":          true,
}

func NewUserRepo(pg *Postgres) *UserRepo {
	return &UserRepo{db: pg}
}

func (r *UserRepo) Create(ctx context.Context, req *models.UserDB) (*models.UserDB, error) {

	query := `
		insert into users 
    	(email, password_hash, first_name, last_name, role)
		values ($1, $2, $3, $4, $5)
		returning id, email, first_name, last_name, role, created_at, updated_at`

	var res models.UserDB
	err := r.db.db.QueryRowxContext(ctx, query,
		req.Email,
		req.PasswordHash,
		req.FirstName,
		req.LastName,
		req.Role,
	).StructScan(&res)

	if err != nil {
		return nil, models.ParseDBError(err)
	}

	return &res, nil
}

func (r *UserRepo) GetPasswordHashByEmail(ctx context.Context, email string) (*models.UserDB, error) {
	query := `select id, email, password_hash, role from users where email = $1 and deleted_at is null`

	var userModel models.UserDB
	err := r.db.db.QueryRowxContext(ctx, query, email).StructScan(&userModel)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, models.ErrUserNotFound
		}
		return nil, models.ParseDBError(err)
	}
	return &userModel, nil

}

func (r *UserRepo) GetUserByID(ctx context.Context, id uuid.UUID) (*models.UserDB, error) {
	query := `
        select id, email, first_name, last_name, role, created_at, updated_at,
               COALESCE((select SUM(value) from votes where target_id = users.id), 0) as rating
        from users 
        where id = $1 and deleted_at is null`
	var userModel models.UserDB
	err := r.db.db.QueryRowxContext(ctx, query, id).StructScan(&userModel)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, models.ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user by id: %w", err)
	}
	return &userModel, nil
}

func (r *UserRepo) Delete(ctx context.Context, id uuid.UUID) error {
	query := `update users set deleted_at = now() where id = $1`
	_, err := r.db.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	return nil
}

func (r *UserRepo) Update(ctx context.Context, id uuid.UUID, fields map[string]any) (*models.UserDB, error) {

	setParts := make([]string, 0, len(fields))
	args := make([]any, 0, len(fields)+1)

	i := 1
	for column, val := range fields {
		if !allowedUpdateColumns[column] {
			return nil, fmt.Errorf("column %s is not allowed", column)
		}
		setParts = append(setParts, fmt.Sprintf("%s = $%d", column, i))
		args = append(args, val)
		i++
	}

	setParts = append(setParts, fmt.Sprintf("updated_at = $%d", i))
	args = append(args, time.Now())

	args = append(args, id)

	query := fmt.Sprintf(`
       UPDATE users
       SET %s
       WHERE id = $%d
       RETURNING id, email, password_hash, first_name, last_name, role, created_at, updated_at,
           COALESCE((select SUM(value) from votes where target_id = users.id), 0) as rating
   `, strings.Join(setParts, ", "), i+1)

	var updatedUser models.UserDB
	err := r.db.db.QueryRowxContext(ctx, query, args...).StructScan(&updatedUser)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, models.ErrUserNotFound
		}
		return nil, err
	}
	return &updatedUser, nil
}

func (r *UserRepo) GetUsers(ctx context.Context, order string, pagination models.Pagination) ([]models.UserDB, uint64, error) {
	sortOrder := "DESC"
	if strings.ToUpper(order) == "ASC" {
		sortOrder = "ASC"
	}
	query := fmt.Sprintf(`
        SELECT id, email, first_name, last_name, role, created_at, updated_at, 
               COALESCE((SELECT SUM(value) FROM votes WHERE target_id = users.id), 0) as rating,
               count(id) over() as total 
        FROM users
        WHERE deleted_at IS NULL
        ORDER BY created_at %s
        LIMIT $1 OFFSET $2`, sortOrder)

	var userDBWithTotal []models.UserDBWithTotal
	err := r.db.db.SelectContext(ctx, &userDBWithTotal, query, pagination.Limit, pagination.Offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get all users: %w", err)
	}

	if len(userDBWithTotal) == 0 {
		return []models.UserDB{}, 0, nil
	}

	total := userDBWithTotal[0].Total

	usersDB := make([]models.UserDB, len(userDBWithTotal))
	for i, user := range userDBWithTotal {
		usersDB[i] = user.UserDB
	}

	return usersDB, total, nil
}

func (r *UserRepo) Vote(ctx context.Context, userID, targetID uuid.UUID, value int) error {
	if value == 0 {
		query := `delete from votes where user_id = $1 and target_id = $2`
		_, err := r.db.db.ExecContext(ctx, query, userID, targetID)
		return err
	}
	query := `
insert into votes (user_id, target_id, value, update_at) values ($1, $2, $3, now())
on conflict (user_id, target_id)
    do update set value = excluded.value, update_at = now()`
	_, err := r.db.db.ExecContext(ctx, query, userID, targetID, value)
	return err
}

func (r *UserRepo) GetLastVoteTime(ctx context.Context, userID uuid.UUID) (time.Time, error) {
	query := `select update_at from votes where user_id = $1 order by update_at desc limit 1`

	var lastVoteTime time.Time
	err := r.db.db.QueryRowxContext(ctx, query, userID).Scan(&lastVoteTime)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return time.Time{}, nil
		}
		return time.Time{}, err
	}
	return lastVoteTime, nil
}
