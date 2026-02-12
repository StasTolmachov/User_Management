package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	mocksCache "foxminded/4_user_management/internal/cache/mocks"
	"foxminded/4_user_management/internal/config"
	"foxminded/4_user_management/internal/models"
	mocks "foxminded/4_user_management/internal/repository/mocks"
	modelsRepo "foxminded/4_user_management/internal/repository/models"
	"foxminded/4_user_management/internal/utils"
	"foxminded/4_user_management/slogger"
)

func TestMain(m *testing.M) {
	slogger.MakeLogger(true)
	code := m.Run()
	os.Exit(code)
}

var jwt = config.JWT{
	Secret: "secret",
	TTL:    10 * time.Minute,
}
var redisErr string = "redis: nil"

func TestUserService_Create(t *testing.T) {
	ctx := t.Context()
	req := models.CreateUserRequest{
		Email:     "test@example.com",
		Password:  "StrongPass1!",
		FirstName: "John",
		LastName:  "Doe",
	}

	tests := []struct {
		name          string
		mockBehavior  func(r *mocks.MockUserRepository)
		expectedError error
	}{
		{
			name: "success",
			mockBehavior: func(r *mocks.MockUserRepository) {
				r.On("Create", ctx, mock.AnythingOfType("*models.UserDB")).Return(&modelsRepo.UserDB{
					ID:        uuid.New(),
					Email:     req.Email,
					FirstName: req.FirstName,
					LastName:  req.LastName,
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				}, nil)
			},
			expectedError: nil,
		},
		{
			name: "Duplicate Email",
			mockBehavior: func(r *mocks.MockUserRepository) {
				r.On("Create", ctx, mock.AnythingOfType("*models.UserDB")).Return(nil, modelsRepo.ErrDuplicateEmail)
			},
			expectedError: models.ErrUserAlreadyExists,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mockRepo := mocks.NewMockUserRepository(t)
			mockCache := mocksCache.NewMockCacheRepository(t)

			tt.mockBehavior(mockRepo)
			service := NewUserService(mockRepo, jwt, mockCache)
			resp, err := service.Create(ctx, req)

			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.Equal(t, req.Email, resp.Email)
			}
			mockRepo.AssertExpectations(t)
		})
	}
}

func TestUserService_Authenticate(t *testing.T) {
	ctx := t.Context()
	email := "user25@com"
	password := "Password1!"
	passwordHash := "$2a$10$3oKmVShrERUMr2pFumIYuOaCJj3iEMFvDLf1//OwuvBEuGlv0y.QO"

	tests := []struct {
		name          string
		mockBehavior  func(r *mocks.MockUserRepository)
		expectedError error
	}{
		{
			name: "success",
			mockBehavior: func(r *mocks.MockUserRepository) {
				r.On("GetPasswordHashByEmail", ctx, email).Return(&modelsRepo.UserDB{
					ID:           uuid.New(),
					Email:        email,
					PasswordHash: "$2a$10$3oKmVShrERUMr2pFumIYuOaCJj3iEMFvDLf1//OwuvBEuGlv0y.QO",
					FirstName:    "John",
					LastName:     "Doe",
					CreatedAt:    time.Now(),
					UpdatedAt:    time.Now(),
				}, nil)
			},
			expectedError: nil,
		},
		{
			name: "ErrUserNotFound",
			mockBehavior: func(r *mocks.MockUserRepository) {
				r.On("GetPasswordHashByEmail", ctx, email).Return(nil, modelsRepo.ErrUserNotFound)
			},
			expectedError: modelsRepo.ErrUserNotFound,
		},
		{
			name: "invalid credentials",
			mockBehavior: func(r *mocks.MockUserRepository) {
				r.On("GetPasswordHashByEmail", ctx, email).Return(&modelsRepo.UserDB{
					ID:           uuid.New(),
					Email:        email,
					PasswordHash: "StrongPass1!",
					FirstName:    "John",
					LastName:     "Doe",
					CreatedAt:    time.Now(),
					UpdatedAt:    time.Now(),
				}, nil)
			},
			expectedError: models.ErrInvalidCredentials,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mockRepo := mocks.NewMockUserRepository(t)
			mockCache := mocksCache.NewMockCacheRepository(t)
			tt.mockBehavior(mockRepo)
			service := NewUserService(mockRepo, jwt, mockCache)

			resp, err := service.Authenticate(ctx, email, password)
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
				assert.Nil(t, resp)

			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.Equal(t, passwordHash, resp.PasswordHash)
			}
			mockRepo.AssertExpectations(t)
		})
	}
}

func TestUserService_GetUserByID(t *testing.T) {
	ctx := t.Context()
	userID := uuid.New()
	cacheKey := fmt.Sprintf("user:%s", userID.String())
	unexpectedErr := errors.New("unexpected error")
	repoResult := &modelsRepo.UserDB{
		ID:           userID,
		Email:        "user25@com",
		PasswordHash: "StrongPass1!",
		FirstName:    "John",
		LastName:     "Doe",
		Role:         "user",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	expectedResponse := models.FromDBToUserResponse(repoResult)

	cachedBytes, _ := json.Marshal(expectedResponse)
	cachedValue := string(cachedBytes)

	tests := []struct {
		name          string
		mockBehavior  func(r *mocks.MockUserRepository, c *mocksCache.MockCacheRepository)
		expectedError error
		expectedBody  *models.UserResponse
	}{

		{
			name: "Success: Cache HIT (Repo not called)",
			mockBehavior: func(r *mocks.MockUserRepository, c *mocksCache.MockCacheRepository) {
				c.On("Get", ctx, cacheKey).Return(cachedValue, nil).Once()

				r.AssertNotCalled(t, "GetUserByID", mock.Anything, mock.Anything)
			},
			expectedBody:  expectedResponse,
			expectedError: nil,
		},
		{
			name: "Success: Cache MISS (Call Repo + Set Cache",
			mockBehavior: func(r *mocks.MockUserRepository, c *mocksCache.MockCacheRepository) {
				c.On("Get", ctx, cacheKey).Return("", errors.New(redisErr)).Once()
				r.On("GetUserByID", ctx, userID).Return(repoResult, nil).Once()
				c.On("Set", ctx, cacheKey, mock.Anything).Return(nil).Once()
			},
			expectedBody:  expectedResponse,
			expectedError: nil,
		},
		{
			name: "Failed: error: ErrUserNotFound",
			mockBehavior: func(r *mocks.MockUserRepository, c *mocksCache.MockCacheRepository) {
				c.On("Get", ctx, cacheKey).Return("", errors.New(redisErr)).Once()
				r.On("GetUserByID", ctx, userID).Return(nil, models.ErrUserNotFound).Once()
			},
			expectedBody:  nil,
			expectedError: models.ErrUserNotFound,
		},
		{
			name: "Failed: error: unexpected error",
			mockBehavior: func(r *mocks.MockUserRepository, c *mocksCache.MockCacheRepository) {
				c.On("Get", ctx, cacheKey).Return("", errors.New(redisErr)).Once()
				r.On("GetUserByID", ctx, userID).Return(nil, unexpectedErr).Once()
			},
			expectedBody:  nil,
			expectedError: unexpectedErr,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mockRepo := mocks.NewMockUserRepository(t)
			mockCache := mocksCache.NewMockCacheRepository(t)
			tt.mockBehavior(mockRepo, mockCache)
			service := NewUserService(mockRepo, jwt, mockCache)

			resp, err := service.GetUserByID(ctx, userID)
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedBody, resp)
			}
			mockRepo.AssertExpectations(t)
		})
	}

}

func TestUserService_Delete(t *testing.T) {
	ctx := t.Context()
	targetID := uuid.New()
	cacheKey := fmt.Sprintf("user:%s", targetID.String())
	unexpectedErr := errors.New("unexpected error")

	tests := []struct {
		name          string
		mockBehavior  func(r *mocks.MockUserRepository, c *mocksCache.MockCacheRepository)
		expectedError error
	}{
		{
			name: "Success: User deleted",
			mockBehavior: func(r *mocks.MockUserRepository, c *mocksCache.MockCacheRepository) {
				r.On("Delete", ctx, targetID).Return(nil).Once()
				c.On("Del", ctx, cacheKey).Return(nil).Once()
			},
			expectedError: nil,
		},
		{
			name: "Failure: User Not Found",
			mockBehavior: func(r *mocks.MockUserRepository, c *mocksCache.MockCacheRepository) {
				r.On("Delete", ctx, targetID).Return(modelsRepo.ErrUserNotFound)
				c.AssertNotCalled(t, "Del", mock.Anything, mock.Anything)
			},
			expectedError: models.ErrUserNotFound,
		},
		{
			name: "Failure: Repo Error",
			mockBehavior: func(r *mocks.MockUserRepository, c *mocksCache.MockCacheRepository) {
				r.On("Delete", ctx, targetID).Return(unexpectedErr)
				c.AssertNotCalled(t, "Del", mock.Anything, mock.Anything)
			},
			expectedError: unexpectedErr,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mockRepo := mocks.NewMockUserRepository(t)
			mockCache := mocksCache.NewMockCacheRepository(t)
			tt.mockBehavior(mockRepo, mockCache)
			service := NewUserService(mockRepo, jwt, mockCache)

			err := service.Delete(ctx, targetID)

			if tt.expectedError != nil {
				assert.Error(t, err)
				if errors.Is(tt.expectedError, models.ErrUserNotFound) {
					assert.ErrorIs(t, err, tt.expectedError)
				} else {
					assert.Contains(t, err.Error(), tt.expectedError.Error())
				}
			} else {
				assert.NoError(t, err)
			}
			mockRepo.AssertExpectations(t)
		})
	}
}

func TestUserService_Update(t *testing.T) {
	ctx := t.Context()
	userID := uuid.New()
	cacheKey := fmt.Sprintf("user:%s", userID.String())
	newEmail := "updated@example.com"
	newPassword := "NewPass1!"

	strPtr := func(s string) *string { return &s }

	repoResult := &modelsRepo.UserDB{
		ID:        userID,
		Email:     newEmail,
		FirstName: "John",
		LastName:  "Doe",
		Role:      "user",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	expectedResponse := models.FromDBToUserResponse(repoResult)

	tests := []struct {
		name          string
		req           models.UpdateUserRequest
		mockBehavior  func(r *mocks.MockUserRepository, c *mocksCache.MockCacheRepository)
		expectedError error
	}{
		{
			name: "Success: Update Email and Password",
			req: models.UpdateUserRequest{
				Email:    strPtr(newEmail),
				Password: strPtr(newPassword),
			},
			mockBehavior: func(r *mocks.MockUserRepository, c *mocksCache.MockCacheRepository) {
				r.On("Update", ctx, userID, mock.MatchedBy(func(fields map[string]any) bool {
					return fields["email"] == newEmail &&
						fields["password_hash"] != nil &&
						fields["password_hash"] != newPassword
				})).Return(&modelsRepo.UserDB{ID: userID, Email: newEmail}, nil).Once()
			},
			expectedError: nil,
		},
		{
			name: "Success: Empty Update (should fetch user)",
			req:  models.UpdateUserRequest{},
			mockBehavior: func(r *mocks.MockUserRepository, c *mocksCache.MockCacheRepository) {
				c.On("Get", ctx, cacheKey).Return("", errors.New(redisErr)).Once()
				r.On("GetUserByID", ctx, userID).Return(repoResult, nil).Once()
				c.On("Set", ctx, cacheKey, mock.Anything).Return(nil).Once()
			},
			expectedError: nil,
		},
		{
			name: "Failure: User Not Found (during Update)",
			req:  models.UpdateUserRequest{Email: strPtr(newEmail)},
			mockBehavior: func(r *mocks.MockUserRepository, c *mocksCache.MockCacheRepository) {
				r.On("Update", ctx, userID, mock.Anything).Return(nil, modelsRepo.ErrUserNotFound)
			},
			expectedError: models.ErrUserNotFound,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mockRepo := mocks.NewMockUserRepository(t)
			mockCache := mocksCache.NewMockCacheRepository(t)
			tt.mockBehavior(mockRepo, mockCache)
			service := NewUserService(mockRepo, jwt, mockCache)

			resp, err := service.Update(ctx, userID, tt.req)

			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.Equal(t, expectedResponse.ID, resp.ID)
				assert.Equal(t, expectedResponse.Email, resp.Email)
			}
			mockRepo.AssertExpectations(t)
		})
	}
}

func TestUserService_GetUsers(t *testing.T) {
	ctx := t.Context()
	unexpectedErr := errors.New("database connection failed")

	user1 := modelsRepo.UserDB{ID: uuid.New(), Email: "u1@e.com", FirstName: "A", LastName: "A", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	user2 := modelsRepo.UserDB{ID: uuid.New(), Email: "u2@e.com", FirstName: "B", LastName: "B", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	user3 := modelsRepo.UserDB{ID: uuid.New(), Email: "u3@e.com", FirstName: "C", LastName: "C", CreatedAt: time.Now(), UpdatedAt: time.Now()}

	usersDB := []modelsRepo.UserDB{user1, user2, user3}
	usersResp := []*models.UserResponse{
		models.FromDBToUserResponse(&user1),
		models.FromDBToUserResponse(&user2),
		models.FromDBToUserResponse(&user3),
	}

	expectedBody := models.ListOfUsersResponse{
		Page:  1,
		Limit: 10,
		Total: 25,
		Pages: 3,
		Data:  usersResp,
	}

	data, _ := json.Marshal(expectedBody)
	cachedValue := string(data)

	tests := []struct {
		name          string
		limit         uint64
		page          uint64
		order         string
		mockBehavior  func(r *mocks.MockUserRepository, c *mocksCache.MockCacheRepository)
		expectedError error
		expectedBody  *models.ListOfUsersResponse
	}{
		{
			name:  "Success: Cache MISS Default Pagination (limit=10, page=1)",
			limit: 0,
			page:  0,
			order: "desc",
			mockBehavior: func(r *mocks.MockUserRepository, c *mocksCache.MockCacheRepository) {
				expectedPagination := modelsRepo.Pagination{Limit: 10, Offset: 0}
				c.On("Get", ctx, mock.Anything).Return("", errors.New(redisErr)).Once()
				r.On("GetUsers", mock.Anything, "desc", expectedPagination).
					Return(usersDB, uint64(25), nil).Once()
				c.On("Set", ctx, mock.Anything, mock.Anything).Return(nil).Once()
			},
			expectedError: nil,
			expectedBody: &models.ListOfUsersResponse{
				Page:  1,
				Limit: 10,
				Total: 25,
				Pages: 3,
				Data:  usersResp,
			},
		},
		{
			name:  "Success: Cache HIT Default Pagination (limit=10, page=1)",
			limit: 0,
			page:  0,
			order: "desc",
			mockBehavior: func(r *mocks.MockUserRepository, c *mocksCache.MockCacheRepository) {
				c.On("Get", ctx, mock.Anything).Return(cachedValue, nil).Once()
				r.AssertNotCalled(t, "GetUsers")
				c.AssertNotCalled(t, "Set")
			},
			expectedError: nil,
			expectedBody: &models.ListOfUsersResponse{
				Page:  1,
				Limit: 10,
				Total: 25,
				Pages: 3,
				Data:  usersResp,
			},
		},
		{
			name:  "Success: Cache MISS Custom Pagination (limit=5, page=2)",
			limit: 5,
			page:  2,
			order: "asc",
			mockBehavior: func(r *mocks.MockUserRepository, c *mocksCache.MockCacheRepository) {
				expectedPagination := modelsRepo.Pagination{Limit: 5, Offset: 5}
				c.On("Get", ctx, mock.Anything).Return("", errors.New(redisErr)).Once()
				r.On("GetUsers", mock.Anything, "asc", expectedPagination).
					Return(usersDB, uint64(12), nil).Once()
				c.On("Set", ctx, mock.Anything, mock.Anything).Return(nil).Once()
			},
			expectedError: nil,
			expectedBody: &models.ListOfUsersResponse{
				Page:  2,
				Limit: 5,
				Total: 12,
				Pages: 3,
				Data:  usersResp,
			},
		},
		{
			name:  "Success: Cache MISS No Users Found",
			limit: 10,
			page:  1,
			order: "desc",
			mockBehavior: func(r *mocks.MockUserRepository, c *mocksCache.MockCacheRepository) {
				expectedPagination := modelsRepo.Pagination{Limit: 10, Offset: 0}
				c.On("Get", ctx, mock.Anything).Return("", errors.New(redisErr)).Once()
				r.On("GetUsers", mock.Anything, "desc", expectedPagination).
					Return([]modelsRepo.UserDB{}, uint64(0), nil).Once()
				c.On("Set", ctx, mock.Anything, mock.Anything).Return(nil).Once()
			},
			expectedError: nil,
			expectedBody: &models.ListOfUsersResponse{
				Page:  1,
				Limit: 10,
				Total: 0,
				Pages: 0,
				Data:  []*models.UserResponse{},
			},
		},
		{
			name:  "Failure: Cache MISS Unexpected Repo Error",
			limit: 10,
			page:  1,
			order: "desc",
			mockBehavior: func(r *mocks.MockUserRepository, c *mocksCache.MockCacheRepository) {
				expectedPagination := modelsRepo.Pagination{Limit: 10, Offset: 0}
				c.On("Get", ctx, mock.Anything).Return("", errors.New(redisErr)).Once()
				r.On("GetUsers", mock.Anything, "desc", expectedPagination).
					Return(nil, uint64(0), unexpectedErr).Once()
				c.AssertNotCalled(t, "Set")
			},
			expectedError: unexpectedErr,
			expectedBody:  nil,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mockRepo := mocks.NewMockUserRepository(t)
			mockCache := mocksCache.NewMockCacheRepository(t)
			tt.mockBehavior(mockRepo, mockCache)
			service := NewUserService(mockRepo, jwt, mockCache)

			resp, err := service.GetUsers(ctx, tt.limit, tt.page, tt.order)

			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)

				assert.Equal(t, tt.expectedBody.Page, resp.Page, "Page mismatch")
				assert.Equal(t, tt.expectedBody.Limit, resp.Limit, "Limit mismatch")
				assert.Equal(t, tt.expectedBody.Total, resp.Total, "Total mismatch")
				assert.Equal(t, tt.expectedBody.Pages, resp.Pages, "Pages mismatch")

				assert.Equal(t, len(tt.expectedBody.Data), len(resp.Data), "Data length mismatch")
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

func TestUserService_Login(t *testing.T) {
	ctx := t.Context()
	email := "test@example.com"
	correctPassword := "StrongPass1!"

	validHash, err := utils.HashPassword(correctPassword)
	assert.NoError(t, err)

	userID := uuid.New()

	tests := []struct {
		name          string
		inputEmail    string
		inputPassword string
		mockBehavior  func(r *mocks.MockUserRepository)
		expectedToken bool
		expectedError error
	}{
		{
			name:          "Success",
			inputEmail:    email,
			inputPassword: correctPassword,
			mockBehavior: func(r *mocks.MockUserRepository) {
				r.On("GetPasswordHashByEmail", ctx, email).Return(&modelsRepo.UserDB{
					ID:           userID,
					Email:        email,
					PasswordHash: validHash,
					Role:         "user",
				}, nil)
			},
			expectedToken: true,
			expectedError: nil,
		},
		{
			name:          "Failure: User Not Found",
			inputEmail:    email,
			inputPassword: correctPassword,
			mockBehavior: func(r *mocks.MockUserRepository) {
				r.On("GetPasswordHashByEmail", ctx, email).Return(nil, modelsRepo.ErrUserNotFound)
			},
			expectedToken: false,
			expectedError: models.ErrInvalidCredentials,
		},
		{
			name:          "Failure: Wrong Password",
			inputEmail:    email,
			inputPassword: "wrong_password",
			mockBehavior: func(r *mocks.MockUserRepository) {
				r.On("GetPasswordHashByEmail", ctx, email).Return(&modelsRepo.UserDB{
					ID:           userID,
					Email:        email,
					PasswordHash: validHash,
					Role:         "user",
				}, nil)
			},
			expectedToken: false,
			expectedError: models.ErrInvalidCredentials,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mockRepo := mocks.NewMockUserRepository(t)
			mockCache := mocksCache.NewMockCacheRepository(t)
			tt.mockBehavior(mockRepo)

			service := NewUserService(mockRepo, jwt, mockCache)

			req := models.LoginRequest{
				Email:    tt.inputEmail,
				Password: tt.inputPassword,
			}
			token, err := service.Login(ctx, req)

			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
				assert.Empty(t, token)
			} else {
				assert.NoError(t, err)
				if tt.expectedToken {
					assert.NotEmpty(t, token)
				}
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

func TestUserService_SyncAdmin(t *testing.T) {
	ctx := t.Context()
	adminCfg := config.Admin{
		Email:    "admin@example.com",
		Password: "SecureAdminPassword1!",
	}
	existingAdminID := uuid.New()
	unexpectedErr := errors.New("db error")

	tests := []struct {
		name          string
		mockBehavior  func(r *mocks.MockUserRepository)
		expectedError error
	}{
		{
			name: "Success: Admin not found, create new",
			mockBehavior: func(r *mocks.MockUserRepository) {
				r.On("GetPasswordHashByEmail", ctx, adminCfg.Email).
					Return(nil, modelsRepo.ErrUserNotFound)

				r.On("Create", ctx, mock.MatchedBy(func(u *modelsRepo.UserDB) bool {
					return u.Email == adminCfg.Email &&
						u.Role == string(models.RoleAdmin) &&
						u.FirstName == "Super" &&
						u.LastName == "Admin" &&
						u.PasswordHash != ""
				})).Return(&modelsRepo.UserDB{
					ID:    uuid.New(),
					Email: adminCfg.Email,
					Role:  string(models.RoleAdmin),
				}, nil)
			},
			expectedError: nil,
		},
		{
			name: "Success: Admin exists, update password and role",
			mockBehavior: func(r *mocks.MockUserRepository) {
				r.On("GetPasswordHashByEmail", ctx, adminCfg.Email).
					Return(&modelsRepo.UserDB{
						ID:    existingAdminID,
						Email: adminCfg.Email,
						Role:  "user",
					}, nil)

				r.On("Update", ctx, existingAdminID, mock.MatchedBy(func(fields map[string]any) bool {
					role, roleOk := fields["role"]
					hash, hashOk := fields["password_hash"]

					return roleOk && role == string(models.RoleAdmin) &&
						hashOk && len(hash.(string)) > 0
				})).Return(&modelsRepo.UserDB{
					ID: existingAdminID,
				}, nil)
			},
			expectedError: nil,
		},
		{
			name: "Failure: GetPasswordHashByEmail Error",
			mockBehavior: func(r *mocks.MockUserRepository) {
				r.On("GetPasswordHashByEmail", ctx, adminCfg.Email).
					Return(nil, unexpectedErr)
			},
			expectedError: unexpectedErr,
		},
		{
			name: "Failure: Create Error",
			mockBehavior: func(r *mocks.MockUserRepository) {
				r.On("GetPasswordHashByEmail", ctx, adminCfg.Email).
					Return(nil, modelsRepo.ErrUserNotFound)

				r.On("Create", ctx, mock.Anything).
					Return(nil, unexpectedErr)
			},
			expectedError: unexpectedErr,
		},
		{
			name: "Failure: Update Error",
			mockBehavior: func(r *mocks.MockUserRepository) {
				r.On("GetPasswordHashByEmail", ctx, adminCfg.Email).
					Return(&modelsRepo.UserDB{ID: existingAdminID}, nil)

				r.On("Update", ctx, existingAdminID, mock.Anything).
					Return(nil, unexpectedErr)
			},
			expectedError: unexpectedErr,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mockRepo := mocks.NewMockUserRepository(t)
			mockCache := mocksCache.NewMockCacheRepository(t)
			tt.mockBehavior(mockRepo)

			service := NewUserService(mockRepo, jwt, mockCache)

			err := service.SyncAdmin(ctx, adminCfg)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
			mockRepo.AssertExpectations(t)
		})
	}
}

func TestUserService_VoteUser(t *testing.T) {
	ctx := t.Context()
	requesterID := uuid.New()
	targetID := uuid.New()
	cacheKey := fmt.Sprintf("user:%s", targetID.String())

	targetUserDB := &modelsRepo.UserDB{
		ID:        targetID,
		Email:     "target@test.com",
		Role:      "user",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	tests := []struct {
		name          string
		req           models.VoteRequest
		requesterID   uuid.UUID
		mockBehavior  func(r *mocks.MockUserRepository, c *mocksCache.MockCacheRepository)
		expectedError error
	}{
		{
			name:        "Success: First Vote (Zero Time)",
			req:         models.VoteRequest{TargetID: targetID, Value: 1},
			requesterID: requesterID,
			mockBehavior: func(r *mocks.MockUserRepository, c *mocksCache.MockCacheRepository) {
				r.On("GetLastVoteTime", ctx, requesterID).
					Return(time.Time{}, nil).Once()

				r.On("Vote", ctx, requesterID, targetID, 1).
					Return(nil).Once()

				c.On("Get", ctx, cacheKey).Return("", errors.New("redis: nil")).Once()
				r.On("GetUserByID", ctx, targetID).Return(targetUserDB, nil).Once()
				c.On("Set", ctx, cacheKey, mock.Anything).Return(nil).Once()
			},
			expectedError: nil,
		},
		{
			name:        "Success: Vote allowed after 1 minute",
			req:         models.VoteRequest{TargetID: targetID, Value: 1},
			requesterID: requesterID,
			mockBehavior: func(r *mocks.MockUserRepository, c *mocksCache.MockCacheRepository) {
				oldTime := time.Now().Add(-2 * time.Minute)
				r.On("GetLastVoteTime", ctx, requesterID).
					Return(oldTime, nil).Once()

				r.On("Vote", ctx, requesterID, targetID, 1).Return(nil).Once()
				c.On("Get", ctx, cacheKey).Return("", errors.New("redis: nil")).Once()
				r.On("GetUserByID", ctx, targetID).Return(targetUserDB, nil).Once()
				c.On("Set", ctx, cacheKey, mock.Anything).Return(nil).Once()
			},
			expectedError: nil,
		},
		{
			name:        "Failure: Self Voting",
			req:         models.VoteRequest{TargetID: requesterID, Value: 1}, // ID совпадают
			requesterID: requesterID,
			mockBehavior: func(r *mocks.MockUserRepository, c *mocksCache.MockCacheRepository) {
				r.AssertNotCalled(t, "GetLastVoteTime", mock.Anything, mock.Anything)
			},
			expectedError: models.ErrSelfVoting,
		},
		{
			name:        "Failure: Rate Limit Exceeded",
			req:         models.VoteRequest{TargetID: targetID, Value: 1},
			requesterID: requesterID,
			mockBehavior: func(r *mocks.MockUserRepository, c *mocksCache.MockCacheRepository) {
				recentTime := time.Now().Add(-30 * time.Second)
				r.On("GetLastVoteTime", ctx, requesterID).
					Return(recentTime, nil).Once()

				r.AssertNotCalled(t, "Vote", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
			},
			expectedError: models.ErrVoteTooOften,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mockRepo := mocks.NewMockUserRepository(t)
			mockCache := mocksCache.NewMockCacheRepository(t)
			tt.mockBehavior(mockRepo, mockCache)

			service := NewUserService(mockRepo, jwt, mockCache)

			resp, err := service.VoteUser(ctx, tt.requesterID, tt.req)

			if tt.expectedError != nil {
				assert.Error(t, err)
				if errors.Is(tt.expectedError, models.ErrSelfVoting) || errors.Is(tt.expectedError, models.ErrVoteTooOften) {
					assert.ErrorIs(t, err, tt.expectedError)
				} else {
					assert.Contains(t, err.Error(), tt.expectedError.Error())
				}
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.Equal(t, targetID.String(), resp.ID)
			}
			mockRepo.AssertExpectations(t)
		})
	}
}
