package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"foxminded/4_user_management/internal/middleware"
	"foxminded/4_user_management/internal/models"
	mocks "foxminded/4_user_management/internal/service/mocks"
	"foxminded/4_user_management/slogger"
)

func TestMain(m *testing.M) {
	slogger.MakeLogger(true)
	code := m.Run()
	os.Exit(code)
}

type ErrorResponse struct {
	Error string `json:"error"`
}

func TestHandler_Create(t *testing.T) {

	mockUserID := uuid.New().String()
	mockTimeStr := "2025-01-01 00:00:00 +0000 UTC"
	successResponse := models.UserResponse{
		ID:        mockUserID,
		Email:     "test@example.com",
		FirstName: "John",
		LastName:  "Doe",
		CreatedAt: mockTimeStr,
		UpdatedAt: mockTimeStr,
	}

	requestBody := models.CreateUserRequest{
		Email:     "test@example.com",
		Password:  "StrongPass1!",
		FirstName: "John",
		LastName:  "Doe",
	}

	tests := []struct {
		name               string
		requestBody        any
		expectedStatusCode int
		expectedBodyJSON   any
		mockBehavior       func(s *mocks.MockUserService)
	}{
		{
			name:               "Success: User created",
			requestBody:        requestBody,
			expectedStatusCode: http.StatusCreated,
			expectedBodyJSON:   successResponse,
			mockBehavior: func(s *mocks.MockUserService) {
				s.On("Create", mock.Anything, requestBody).
					Return(&successResponse, nil).Once()
			},
		},
		{
			name:               "Failure: Duplicate Email (Conflict)",
			requestBody:        requestBody,
			expectedStatusCode: http.StatusConflict,
			expectedBodyJSON:   ErrorResponse{Error: "User already exists"},
			mockBehavior: func(s *mocks.MockUserService) {
				s.On("Create", mock.Anything, requestBody).
					Return(nil, models.ErrUserAlreadyExists).Once()
			},
		},
		{
			name:               "Failure: Invalid Request Body (Invalid JSON)",
			requestBody:        "this is not json", // Невалидный JSON
			expectedStatusCode: http.StatusBadRequest,
			expectedBodyJSON:   ErrorResponse{Error: "Invalid request body"},
			mockBehavior: func(s *mocks.MockUserService) {
				s.AssertNotCalled(t, "Create", mock.Anything, mock.Anything)
			},
		},

		{
			name: "Failure: Missing Field (Empty Email)",
			requestBody: models.CreateUserRequest{
				Email:     "",
				Password:  "StrongPass1!",
				FirstName: "John",
				LastName:  "Doe",
			},
			expectedStatusCode: http.StatusBadRequest,
			expectedBodyJSON:   ErrorResponse{Error: "Fields cannot be empty"},
			mockBehavior: func(s *mocks.MockUserService) {
				s.AssertNotCalled(t, "Create", mock.Anything, mock.Anything)
			},
		},
		{
			name:               "Failure: Internal Service Error",
			requestBody:        requestBody,
			expectedStatusCode: http.StatusInternalServerError,
			expectedBodyJSON:   ErrorResponse{Error: "database connection failed"},
			mockBehavior: func(s *mocks.MockUserService) {
				s.On("Create", mock.Anything, requestBody).
					Return(nil, errors.New("database connection failed")).Once()
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mockService := mocks.NewMockUserService(t)
			tt.mockBehavior(mockService)

			handler := NewHandler(mockService)

			bodyBytes, err := json.Marshal(tt.requestBody)
			if err != nil && tt.name != "Failure: Invalid Request Body (Invalid JSON)" {
				t.Fatalf("Failed to marshal request body: %v", err)
			}

			reqBody := bytes.NewReader(bodyBytes)

			req := httptest.NewRequest(http.MethodPost, "/api/v1/users", reqBody)
			req.Header.Set("Content-Type", "application/json")

			rr := httptest.NewRecorder()

			handler.Create(rr, req)

			assert.Equal(t, tt.expectedStatusCode, rr.Code)

			if tt.expectedBodyJSON != nil {
				if tt.expectedStatusCode == http.StatusCreated {
					var actualResponse models.UserResponse
					err := json.Unmarshal(rr.Body.Bytes(), &actualResponse)
					assert.NoError(t, err, "Failed to unmarshal successful response body")

					expected := tt.expectedBodyJSON.(models.UserResponse)

					assert.Equal(t, expected.ID, actualResponse.ID, "ID mismatch")
					assert.Equal(t, expected.Email, actualResponse.Email, "Email mismatch")
					assert.Equal(t, expected.FirstName, actualResponse.FirstName, "FirstName mismatch")
					assert.Equal(t, expected.LastName, actualResponse.LastName, "LastName mismatch")

					assert.NotEmpty(t, actualResponse.CreatedAt, "CreatedAt should not be empty")
					assert.NotEmpty(t, actualResponse.UpdatedAt, "UpdatedAt should not be empty")

				} else {
					expectedJSON, _ := json.Marshal(tt.expectedBodyJSON)
					assert.JSONEq(t, string(expectedJSON), rr.Body.String(), "Тело ответа ошибки не совпадает")
				}
			}

			mockService.AssertExpectations(t)
		})
	}
}

func TestHandler_GetUserByID(t *testing.T) {
	userID := uuid.New()
	userResponse := models.UserResponse{
		ID:        userID.String(),
		Email:     "get@example.com",
		FirstName: "Get",
		LastName:  "User",
	}

	tests := []struct {
		name               string
		urlParamID         string
		expectedStatusCode int
		expectedBody       any
		mockBehavior       func(s *mocks.MockUserService)
	}{
		{
			name:               "Success: User found",
			urlParamID:         userID.String(),
			expectedStatusCode: http.StatusOK,
			expectedBody:       userResponse,
			mockBehavior: func(s *mocks.MockUserService) {
				s.On("GetUserByID", mock.Anything, userID).
					Return(&userResponse, nil).Once()
			},
		},
		{
			name:               "Failure: Invalid UUID",
			urlParamID:         "not-a-uuid",
			expectedStatusCode: http.StatusBadRequest,
			expectedBody:       ErrorResponse{Error: "Invalid user ID"},
			mockBehavior: func(s *mocks.MockUserService) {
				s.AssertNotCalled(t, "GetUserByID", mock.Anything, mock.Anything)
			},
		},
		{
			name:               "Failure: User Not Found",
			urlParamID:         userID.String(),
			expectedStatusCode: http.StatusNotFound,
			expectedBody:       ErrorResponse{Error: "User not found"},
			mockBehavior: func(s *mocks.MockUserService) {
				s.On("GetUserByID", mock.Anything, userID).
					Return(nil, models.ErrUserNotFound).Once()
			},
		},
		{
			name:               "Failure: Internal Service Error",
			urlParamID:         userID.String(),
			expectedStatusCode: http.StatusInternalServerError,
			expectedBody:       ErrorResponse{Error: "Failed to get user"},
			mockBehavior: func(s *mocks.MockUserService) {
				s.On("GetUserByID", mock.Anything, userID).
					Return(nil, errors.New("unexpected error")).Once()
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mockService := mocks.NewMockUserService(t)
			tt.mockBehavior(mockService)

			handler := NewHandler(mockService)

			r := chi.NewRouter()
			r.Get("/users/{id}", handler.GetUserByID)

			req := httptest.NewRequest(http.MethodGet, "/users/"+tt.urlParamID, nil)
			rr := httptest.NewRecorder()

			r.ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatusCode, rr.Code)

			if tt.expectedBody != nil {
				if tt.expectedStatusCode == http.StatusOK {
					var actualResp models.UserResponse
					err := json.Unmarshal(rr.Body.Bytes(), &actualResp)
					assert.NoError(t, err)

					expected := tt.expectedBody.(models.UserResponse)
					assert.Equal(t, expected.ID, actualResp.ID)
					assert.Equal(t, expected.Email, actualResp.Email)
				} else {
					expectedJSON, _ := json.Marshal(tt.expectedBody)
					assert.JSONEq(t, string(expectedJSON), rr.Body.String())
				}
			}

			mockService.AssertExpectations(t)
		})
	}
}

func TestHandler_GetUsers(t *testing.T) {
	usersResp := &models.ListOfUsersResponse{
		Page:  1,
		Limit: 10,
		Total: 1,
		Pages: 1,
		Data: []*models.UserResponse{
			{ID: "1", Email: "u1@example.com"},
		},
	}

	tests := []struct {
		name               string
		queryString        string
		expectedStatusCode int
		expectedBody       any
		mockBehavior       func(s *mocks.MockUserService)
	}{
		{
			name:               "Success: Default params",
			queryString:        "",
			expectedStatusCode: http.StatusOK,
			expectedBody:       usersResp,
			mockBehavior: func(s *mocks.MockUserService) {
				s.On("GetUsers", mock.Anything, uint64(10), uint64(1), "desc").
					Return(usersResp, nil).Once()
			},
		},
		{
			name:               "Success: Custom params",
			queryString:        "?limit=5&page=2&order=asc",
			expectedStatusCode: http.StatusOK,
			expectedBody:       usersResp,
			mockBehavior: func(s *mocks.MockUserService) {
				s.On("GetUsers", mock.Anything, uint64(5), uint64(2), "asc").
					Return(usersResp, nil).Once()
			},
		},
		{
			name:               "Failure: Invalid Limit (Not a number)",
			queryString:        "?limit=abc",
			expectedStatusCode: http.StatusBadRequest,
			expectedBody:       ErrorResponse{Error: "Invalid limit"},
			mockBehavior: func(s *mocks.MockUserService) {
				s.AssertNotCalled(t, "GetUsers", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
			},
		},
		{
			name:               "Failure: Invalid Page (Not a number)",
			queryString:        "?page=xyz",
			expectedStatusCode: http.StatusBadRequest,
			expectedBody:       ErrorResponse{Error: "Invalid page"},
			mockBehavior: func(s *mocks.MockUserService) {
				s.AssertNotCalled(t, "GetUsers", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
			},
		},
		{
			name:               "Failure: Service Error",
			queryString:        "",
			expectedStatusCode: http.StatusInternalServerError,
			expectedBody:       ErrorResponse{Error: "Failed to get users"},
			mockBehavior: func(s *mocks.MockUserService) {
				s.On("GetUsers", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(nil, errors.New("db error")).Once()
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mockService := mocks.NewMockUserService(t)
			tt.mockBehavior(mockService)

			handler := NewHandler(mockService)

			req := httptest.NewRequest(http.MethodGet, "/api/v1/users"+tt.queryString, nil)
			rr := httptest.NewRecorder()

			handler.GetUsers(rr, req)

			assert.Equal(t, tt.expectedStatusCode, rr.Code)

			if tt.expectedStatusCode == http.StatusOK {
				expectedJSON, _ := json.Marshal(tt.expectedBody)
				assert.JSONEq(t, string(expectedJSON), rr.Body.String())
			} else {
				expectedJSON, _ := json.Marshal(tt.expectedBody)
				assert.JSONEq(t, string(expectedJSON), rr.Body.String())
			}

			mockService.AssertExpectations(t)
		})
	}
}

func TestHandler_Delete(t *testing.T) {
	adminID := uuid.New()
	moderatorID := uuid.New()
	userID := uuid.New()
	otherUserID := uuid.New()

	adminUser := &models.User{ID: adminID, Role: models.RoleAdmin}
	moderatorUser := &models.User{ID: moderatorID, Role: models.RoleModerator}
	simpleUser := &models.User{ID: userID, Role: models.RoleUser}

	targetUserResp := &models.UserResponse{ID: otherUserID.String(), Role: string(models.RoleUser)}
	targetAdminResp := &models.UserResponse{ID: adminID.String(), Role: string(models.RoleAdmin)}

	tests := []struct {
		name               string
		targetID           string
		requester          *models.User
		expectedStatusCode int
		mockBehavior       func(s *mocks.MockUserService)
	}{
		{
			name:               "Success: Admin deletes User",
			targetID:           otherUserID.String(),
			requester:          adminUser,
			expectedStatusCode: http.StatusOK,
			mockBehavior: func(s *mocks.MockUserService) {
				s.On("GetUserByID", mock.Anything, otherUserID).Return(targetUserResp, nil).Once()
				s.On("Delete", mock.Anything, otherUserID).Return(nil).Once()
			},
		},
		{
			name:               "Success: User deletes Self",
			targetID:           userID.String(),
			requester:          simpleUser,
			expectedStatusCode: http.StatusOK,
			mockBehavior: func(s *mocks.MockUserService) {
				selfResp := &models.UserResponse{ID: userID.String(), Role: string(models.RoleUser)}
				s.On("GetUserByID", mock.Anything, userID).Return(selfResp, nil).Once()
				s.On("Delete", mock.Anything, userID).Return(nil).Once()
			},
		},
		{
			name:               "Success: Moderator deletes User",
			targetID:           otherUserID.String(),
			requester:          moderatorUser,
			expectedStatusCode: http.StatusOK,
			mockBehavior: func(s *mocks.MockUserService) {
				s.On("GetUserByID", mock.Anything, otherUserID).Return(targetUserResp, nil).Once()
				s.On("Delete", mock.Anything, otherUserID).Return(nil).Once()
			},
		},
		{
			name:               "Failure: User tries to delete Another User (Permission Denied)",
			targetID:           otherUserID.String(),
			requester:          simpleUser,
			expectedStatusCode: http.StatusForbidden,
			mockBehavior: func(s *mocks.MockUserService) {
				s.On("GetUserByID", mock.Anything, otherUserID).Return(targetUserResp, nil).Once()
				s.AssertNotCalled(t, "Delete", mock.Anything, mock.Anything)
			},
		},
		{
			name:               "Failure: Moderator tries to delete Admin (Permission Denied)",
			targetID:           adminID.String(),
			requester:          moderatorUser,
			expectedStatusCode: http.StatusForbidden,
			mockBehavior: func(s *mocks.MockUserService) {
				s.On("GetUserByID", mock.Anything, adminID).Return(targetAdminResp, nil).Once()
				s.AssertNotCalled(t, "Delete", mock.Anything, mock.Anything)
			},
		},
		{
			name:               "Failure: GetUserByID Error (Internal Server Error)",
			targetID:           otherUserID.String(),
			requester:          adminUser,
			expectedStatusCode: http.StatusInternalServerError,
			mockBehavior: func(s *mocks.MockUserService) {
				s.On("GetUserByID", mock.Anything, otherUserID).Return(nil, errors.New("db error")).Once()
				s.AssertNotCalled(t, "Delete", mock.Anything, mock.Anything)
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mockService := mocks.NewMockUserService(t)
			tt.mockBehavior(mockService)

			handler := NewHandler(mockService)

			r := chi.NewRouter()
			r.Delete("/users/{id}", handler.Delete)

			req := httptest.NewRequest(http.MethodDelete, "/users/"+tt.targetID, nil)

			ctx := context.WithValue(req.Context(), middleware.UserCtxKey{}, tt.requester)
			req = req.WithContext(ctx)

			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatusCode, rr.Code)
			mockService.AssertExpectations(t)
		})
	}
}

func TestHandler_Update(t *testing.T) {
	userID := uuid.New()
	otherID := uuid.New()

	strPtr := func(s string) *string { return &s }

	userRequester := &models.User{ID: userID, Role: models.RoleUser}
	adminRequester := &models.User{ID: uuid.New(), Role: models.RoleAdmin}

	targetUserResp := &models.UserResponse{ID: userID.String(), Role: string(models.RoleUser)}
	targetOtherResp := &models.UserResponse{ID: otherID.String(), Role: string(models.RoleUser)}

	updateReq := models.UpdateUserRequest{FirstName: strPtr("NewName")}

	tests := []struct {
		name               string
		targetID           string
		requester          *models.User
		requestBody        any
		expectedStatusCode int
		mockBehavior       func(s *mocks.MockUserService)
	}{
		{
			name:               "Success: User updates Self",
			targetID:           userID.String(),
			requester:          userRequester,
			requestBody:        updateReq,
			expectedStatusCode: http.StatusOK,
			mockBehavior: func(s *mocks.MockUserService) {
				s.On("GetUserByID", mock.Anything, userID).Return(targetUserResp, nil).Once()
				s.On("Update", mock.Anything, userID, updateReq).Return(&models.UserResponse{}, nil).Once()
			},
		},
		{
			name:               "Failure: User updates Another (Forbidden)",
			targetID:           otherID.String(),
			requester:          userRequester,
			requestBody:        updateReq,
			expectedStatusCode: http.StatusForbidden,
			mockBehavior: func(s *mocks.MockUserService) {
				s.On("GetUserByID", mock.Anything, otherID).Return(targetOtherResp, nil).Once()
				s.AssertNotCalled(t, "Update", mock.Anything, mock.Anything, mock.Anything)
			},
		},
		{
			name:               "Failure: User tries to update Role (Forbidden Param)",
			targetID:           userID.String(),
			requester:          userRequester,
			requestBody:        models.UpdateUserRequest{Role: strPtr("admin")},
			expectedStatusCode: http.StatusBadRequest,
			mockBehavior: func(s *mocks.MockUserService) {
				s.On("GetUserByID", mock.Anything, userID).Return(targetUserResp, nil).Once()
				s.AssertNotCalled(t, "Update", mock.Anything, mock.Anything, mock.Anything)
			},
		},
		{
			name:               "Success: Admin updates User Role",
			targetID:           otherID.String(),
			requester:          adminRequester,
			requestBody:        models.UpdateUserRequest{Role: strPtr("moderator")},
			expectedStatusCode: http.StatusOK,
			mockBehavior: func(s *mocks.MockUserService) {
				s.On("GetUserByID", mock.Anything, otherID).Return(targetOtherResp, nil).Once()
				s.On("Update", mock.Anything, otherID, mock.Anything).Return(&models.UserResponse{}, nil).Once()
			},
		},
		{
			name:               "Failure: Invalid JSON",
			targetID:           userID.String(),
			requester:          userRequester,
			requestBody:        "invalid-json",
			expectedStatusCode: http.StatusBadRequest,
			mockBehavior: func(s *mocks.MockUserService) {
				s.On("GetUserByID", mock.Anything, userID).Return(targetUserResp, nil).Once()
				s.AssertNotCalled(t, "Update", mock.Anything, mock.Anything, mock.Anything)
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mockService := mocks.NewMockUserService(t)
			tt.mockBehavior(mockService)
			handler := NewHandler(mockService)

			r := chi.NewRouter()
			r.Put("/users/{id}", handler.Update)

			var bodyReader *bytes.Reader
			if s, ok := tt.requestBody.(string); ok {
				bodyReader = bytes.NewReader([]byte(s))
			} else {
				jsonBytes, _ := json.Marshal(tt.requestBody)
				bodyReader = bytes.NewReader(jsonBytes)
			}

			req := httptest.NewRequest(http.MethodPut, "/users/"+tt.targetID, bodyReader)
			ctx := context.WithValue(req.Context(), middleware.UserCtxKey{}, tt.requester)
			req = req.WithContext(ctx)

			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatusCode, rr.Code)
			mockService.AssertExpectations(t)
		})
	}
}

func TestHandler_Login(t *testing.T) {
	request := models.LoginRequest{
		Email:    "test@test.com",
		Password: "password",
	}
	token := "token"
	tests := []struct {
		name               string
		requestBody        any
		expectedStatusCode int
		expectedBody       any
		mockBehavior       func(s *mocks.MockUserService)
	}{
		{
			name:               "Success: Valid credentials",
			requestBody:        request,
			expectedStatusCode: http.StatusOK,
			expectedBody:       models.LoginResponse{Token: token},
			mockBehavior: func(s *mocks.MockUserService) {
				s.On("Login", mock.Anything, request).Return(token, nil).Once()
			},
		},
		{
			name:               "Failure: Invalid credentials",
			requestBody:        request,
			expectedStatusCode: http.StatusUnauthorized,
			expectedBody:       ErrorResponse{Error: "Invalid email or password"},
			mockBehavior: func(s *mocks.MockUserService) {
				s.On("Login", mock.Anything, request).Return("", models.ErrInvalidCredentials).Once()
			},
		},
		{
			name:               "Failure: Internal Server Error",
			requestBody:        request,
			expectedStatusCode: http.StatusInternalServerError,
			expectedBody:       ErrorResponse{Error: "Internal server error"},
			mockBehavior: func(s *mocks.MockUserService) {
				s.On("Login", mock.Anything, request).Return("", errors.New("unexpected error")).Once()
			},
		},
		{
			name:               "Failure: Invalid JSON Body",
			requestBody:        "invalid-json",
			expectedStatusCode: http.StatusBadRequest,
			expectedBody:       ErrorResponse{Error: "Invalid request body"},
			mockBehavior: func(s *mocks.MockUserService) {
				s.AssertNotCalled(t, "Login", mock.Anything, mock.Anything)
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mockService := mocks.NewMockUserService(t)
			tt.mockBehavior(mockService)

			handler := NewHandler(mockService)

			var reqBodyReader *bytes.Reader
			if s, ok := tt.requestBody.(string); ok {
				reqBodyReader = bytes.NewReader([]byte(s))
			} else {
				bodyBytes, _ := json.Marshal(tt.requestBody)
				reqBodyReader = bytes.NewReader(bodyBytes)
			}

			req := httptest.NewRequest(http.MethodPost, "/api/v1/login", reqBodyReader)
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			handler.Login(rr, req)

			assert.Equal(t, tt.expectedStatusCode, rr.Code)

			if tt.expectedBody != nil {
				expectedJSON, _ := json.Marshal(tt.expectedBody)
				assert.JSONEq(t, string(expectedJSON), rr.Body.String())
			}

			mockService.AssertExpectations(t)
		})
	}
}

func TestHandler_Vote(t *testing.T) {
	requesterID := uuid.New()
	targetID := uuid.New()

	requesterUser := &models.User{
		ID:   requesterID,
		Role: models.RoleUser,
	}

	successResp := &models.UserResponse{
		ID:     targetID.String(),
		Rating: 1,
	}

	tests := []struct {
		name               string
		targetIDStr        string
		inputBody          map[string]int
		mockBehavior       func(s *mocks.MockUserService)
		expectedStatusCode int
		expectedBody       string
	}{
		{
			name:        "Success: Vote +1",
			targetIDStr: targetID.String(),
			inputBody:   map[string]int{"value": 1},
			mockBehavior: func(s *mocks.MockUserService) {
				expectedReq := models.VoteRequest{
					TargetID: targetID,
					Value:    1,
				}
				s.On("VoteUser", mock.Anything, requesterID, expectedReq).
					Return(successResp, nil).Once()
			},
			expectedStatusCode: http.StatusOK,
			expectedBody:       `"rating":1`,
		},
		{
			name:        "Failure: Invalid Target ID (URL Validation)",
			targetIDStr: "invalid-uuid-string",
			inputBody:   map[string]int{"value": 1},
			mockBehavior: func(s *mocks.MockUserService) {
				s.AssertNotCalled(t, "VoteUser", mock.Anything, mock.Anything, mock.Anything)
			},
			expectedStatusCode: http.StatusBadRequest,
			expectedBody:       "Invalid user ID",
		},
		{
			name:        "Failure: Invalid Value (Body Validation)",
			targetIDStr: targetID.String(),
			inputBody:   map[string]int{"value": 5},
			mockBehavior: func(s *mocks.MockUserService) {
				s.AssertNotCalled(t, "VoteUser", mock.Anything, mock.Anything, mock.Anything)
			},
			expectedStatusCode: http.StatusBadRequest,
			expectedBody:       "Invalid value",
		},
		{
			name:        "Failure: Self Voting (Service Error)",
			targetIDStr: requesterID.String(),
			inputBody:   map[string]int{"value": 1},
			mockBehavior: func(s *mocks.MockUserService) {
				expectedReq := models.VoteRequest{
					TargetID: requesterID,
					Value:    1,
				}
				s.On("VoteUser", mock.Anything, requesterID, expectedReq).
					Return(nil, models.ErrSelfVoting).Once()
			},
			expectedStatusCode: http.StatusBadRequest,
			expectedBody:       models.ErrSelfVoting.Error(),
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockService := mocks.NewMockUserService(t)
			tt.mockBehavior(mockService)
			handler := NewHandler(mockService)

			r := chi.NewRouter()
			r.Post("/users/{id}/vote", handler.Vote)

			bodyBytes, _ := json.Marshal(tt.inputBody)
			req := httptest.NewRequest(http.MethodPost, "/users/"+tt.targetIDStr+"/vote", bytes.NewReader(bodyBytes))

			ctx := context.WithValue(req.Context(), middleware.UserCtxKey{}, requesterUser)
			req = req.WithContext(ctx)

			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatusCode, rr.Code)
			if tt.expectedBody != "" {
				assert.Contains(t, rr.Body.String(), tt.expectedBody)
			}

			mockService.AssertExpectations(t)
		})
	}
}
