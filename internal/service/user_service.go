package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"foxminded/4_user_management/internal/cache"
	"foxminded/4_user_management/internal/config"
	"foxminded/4_user_management/internal/models"
	"foxminded/4_user_management/internal/repository"
	modelsRepo "foxminded/4_user_management/internal/repository/models"
	"foxminded/4_user_management/internal/utils"
	"foxminded/4_user_management/slogger"
)

type userService struct {
	repo  repository.UserRepository
	jwt   config.JWT
	cache cache.CacheRepository
}

func NewUserService(repo repository.UserRepository, jwt config.JWT, cacheClient cache.CacheRepository) UserService {
	return &userService{
		repo:  repo,
		jwt:   jwt,
		cache: cacheClient,
	}
}

type UserService interface {
	Create(ctx context.Context, req models.CreateUserRequest) (*models.UserResponse, error)
	Authenticate(ctx context.Context, email, password string) (*models.User, error)
	GetUserByID(ctx context.Context, id uuid.UUID) (*models.UserResponse, error)
	Delete(ctx context.Context, targetID uuid.UUID) error
	Update(ctx context.Context, id uuid.UUID, req models.UpdateUserRequest) (*models.UserResponse, error)
	GetUsers(ctx context.Context, limit, page uint64, order string) (*models.ListOfUsersResponse, error)
	Login(ctx context.Context, req models.LoginRequest) (string, error)
	SyncAdmin(ctx context.Context, adminCfg config.Admin) error
	VoteUser(ctx context.Context, requesterID uuid.UUID, req models.VoteRequest) (*models.UserResponse, error)
}

func (s *userService) Create(ctx context.Context, req models.CreateUserRequest) (*models.UserResponse, error) {
	userRequest, err := models.NewUser(req, models.RoleUser)
	if err != nil {
		return nil, fmt.Errorf("invalid user data")
	}

	userDB, err := s.repo.Create(ctx, models.ToUserDB(userRequest))

	if err != nil {
		if errors.Is(err, modelsRepo.ErrDuplicateEmail) {
			return nil, models.ErrUserAlreadyExists
		}
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return models.FromDBToUserResponse(userDB), nil
}

func (s *userService) Login(ctx context.Context, req models.LoginRequest) (string, error) {
	userDB, err := s.repo.GetPasswordHashByEmail(ctx, req.Email)
	slogger.Log.DebugContext(ctx, "Login request", "userDB", userDB)
	if err != nil {
		if errors.Is(err, modelsRepo.ErrUserNotFound) {
			return "", models.ErrInvalidCredentials
		}
		return "", fmt.Errorf("failed to get user by email: %w", err)
	}
	if !utils.ComparePasswords(userDB.PasswordHash, req.Password) {
		return "", models.ErrInvalidCredentials
	}
	token, err := utils.GenerateToken(userDB.ID, userDB.Role, s.jwt)
	if err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}
	return token, nil
}

func (s *userService) SyncAdmin(ctx context.Context, adminCfg config.Admin) error {
	slogger.Log.InfoContext(ctx, "Syncing admin user...", "email", adminCfg.Email)

	userDB, err := s.repo.GetPasswordHashByEmail(ctx, adminCfg.Email)
	if err != nil {
		if errors.Is(err, modelsRepo.ErrUserNotFound) {
			slogger.Log.InfoContext(ctx, "Admin not found, creating new one")
			req := models.CreateUserRequest{
				Email:     adminCfg.Email,
				Password:  adminCfg.Password,
				FirstName: "Super",
				LastName:  "Admin",
			}
			newUser, err := models.NewUser(req, models.RoleAdmin)
			if err != nil {
				return fmt.Errorf("invalid admin data")
			}
			_, err = s.repo.Create(ctx, models.ToUserDB(newUser))
			if err != nil {
				return fmt.Errorf("failed to create admin: %w", err)
			}
			return nil
		}
		return err
	}

	hash, err := utils.HashPassword(adminCfg.Password)
	if err != nil {
		return err
	}

	fields := map[string]any{
		"password_hash": hash,
		"role":          string(models.RoleAdmin),
	}

	_, err = s.repo.Update(ctx, userDB.ID, fields)
	if err != nil {
		return fmt.Errorf("failed to update admin: %w", err)
	}
	slogger.Log.InfoContext(ctx, "Admin user synced successfully")

	return nil
}

func (s *userService) Authenticate(ctx context.Context, email, password string) (*models.User, error) {
	user, err := s.repo.GetPasswordHashByEmail(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}

	if !utils.ComparePasswords(user.PasswordHash, password) {
		return nil, models.ErrInvalidCredentials
	}
	return models.FromUserDB(user), nil
}

// GetUserByID retrieves a user by their ID, checking cache first before querying the repository.
// If found in cache, it unmarshals the data and returns the user; otherwise, fetches from the repository and updates the cache.
// Returns a UserResponse object or an error if the user is not found or if any other issue occurs.
func (s *userService) GetUserByID(ctx context.Context, id uuid.UUID) (*models.UserResponse, error) {
	cacheKey := fmt.Sprintf("user:%s", id.String())

	val, err := s.cache.Get(ctx, cacheKey)
	if err == nil {
		slogger.Log.DebugContext(ctx, "Cache HIT for user", "id", id)

		var userResp models.UserResponse
		if err := json.Unmarshal([]byte(val), &userResp); err == nil {
			return &userResp, nil
		}
	} else if !errors.Is(err, redis.Nil) {
		slogger.Log.ErrorContext(ctx, "Redis error", "err", err)
	}

	slogger.Log.DebugContext(ctx, "Cache MISS for user", "id", id)
	user, err := s.repo.GetUserByID(ctx, id)
	if err != nil {
		if errors.Is(err, modelsRepo.ErrUserNotFound) {
			return nil, models.ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to GetUserByID: %w", err)
	}
	response := models.FromDBToUserResponse(user)

	data, err := json.Marshal(response)
	if err == nil {
		_ = s.cache.Set(ctx, cacheKey, data)
	} else {
		slogger.Log.ErrorContext(ctx, "Failed to marshal user for cache", "err", err)
	}
	return response, nil
}

func (s *userService) Delete(ctx context.Context, targetID uuid.UUID) error {
	cacheKey := fmt.Sprintf("user:%s", targetID.String())

	err := s.repo.Delete(ctx, targetID)
	if err != nil {
		if errors.Is(err, modelsRepo.ErrUserNotFound) {
			return models.ErrUserNotFound
		}
		return fmt.Errorf("failed to delete user: %w", err)
	}
	err = s.cache.Del(ctx, cacheKey)
	if err != nil {
		slogger.Log.ErrorContext(ctx, "Failed to delete from redis", "err", err)
	}
	return nil
}

func (s *userService) Update(ctx context.Context, id uuid.UUID, req models.UpdateUserRequest) (*models.UserResponse, error) {

	fields := map[string]any{}
	var err error

	if req.Email != nil {
		fields["email"] = *req.Email
	}
	if req.Password != nil {
		fields["password_hash"], err = utils.HashPassword(*req.Password)
		if err != nil {
			return nil, err
		}
	}
	if req.FirstName != nil {
		fields["first_name"] = *req.FirstName
	}
	if req.LastName != nil {
		fields["last_name"] = *req.LastName
	}
	if req.Role != nil {
		fields["role"] = *req.Role
	}

	if len(fields) == 0 {
		currentUser, err := s.GetUserByID(ctx, id)
		if err != nil {
			if errors.Is(err, modelsRepo.ErrUserNotFound) {
				return nil, models.ErrUserNotFound
			}
			return nil, fmt.Errorf("failed to get user by id: %w", err)
		}
		return currentUser, nil
	}
	updated, err := s.repo.Update(ctx, id, fields)
	slogger.Log.DebugContext(ctx, "UpdateUser from repo update", "updatedUserID", id, "err", err, "updated user:", updated)
	if err != nil {
		if errors.Is(err, modelsRepo.ErrUserNotFound) {
			return nil, models.ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to update user s.repo.Update: %w", err)
	}

	return models.FromDBToUserResponse(updated), nil
}

func (s *userService) GetUsers(ctx context.Context, limit, page uint64, order string) (*models.ListOfUsersResponse, error) {
	if limit == 0 {
		limit = 10
	}
	if page == 0 {
		page = 1
	}

	cacheKey := fmt.Sprintf("users:%d:%d:%s", limit, page, order)

	val, err := s.cache.Get(ctx, cacheKey)
	if err == nil {
		slogger.Log.DebugContext(ctx, "Cache HIT for user", "limit", limit, "page", page, "order", order)
		var resp models.ListOfUsersResponse
		if err := json.Unmarshal([]byte(val), &resp); err == nil {
			return &resp, nil
		}
	}

	offset := (page - 1) * limit
	pagination := &modelsRepo.Pagination{
		Limit:  limit,
		Offset: offset,
	}
	usersDB, total, err := s.repo.GetUsers(ctx, order, *pagination)
	slogger.Log.DebugContext(ctx, "s.repo.GetUsers", "err", err)
	if err != nil {
		return nil, err
	}

	usersResponse := make([]*models.UserResponse, len(usersDB))
	for i, userModel := range usersDB {
		usersResponse[i] = models.FromDBToUserResponse(&userModel)
	}

	pages := (total + limit - 1) / limit

	resp := &models.ListOfUsersResponse{
		Page:  page,
		Limit: limit,
		Total: total,
		Pages: pages,
		Data:  usersResponse,
	}
	data, err := json.Marshal(resp)
	slogger.Log.DebugContext(ctx, "cache set marshal error", "err", err)
	if err == nil {
		_ = s.cache.Set(ctx, cacheKey, data)
	}

	return resp, nil
}

func (s *userService) VoteUser(ctx context.Context, requesterID uuid.UUID, req models.VoteRequest) (*models.UserResponse, error) {

	if requesterID == req.TargetID {
		return nil, models.ErrSelfVoting
	}

	lastVoteTime, err := s.repo.GetLastVoteTime(ctx, requesterID)
	if err != nil {
		return nil, fmt.Errorf("failed to get last vote time: %w", err)
	}

	if !lastVoteTime.IsZero() && time.Since(lastVoteTime) < time.Minute {
		return nil, models.ErrVoteTooOften
	}

	err = s.repo.Vote(ctx, requesterID, req.TargetID, req.Value)
	if err != nil {
		return nil, fmt.Errorf("failed to vote user: %w", err)
	}
	return s.GetUserByID(ctx, req.TargetID)
}
