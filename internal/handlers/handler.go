package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	httpSwagger "github.com/swaggo/http-swagger"

	"foxminded/4_user_management/internal/middleware"
	"foxminded/4_user_management/internal/models"
	"foxminded/4_user_management/internal/service"
	"foxminded/4_user_management/internal/utils"
	"foxminded/4_user_management/slogger"
)

type Handler struct {
	userService service.UserService
}

const ctxWithTimeout time.Duration = time.Second * 5

func NewHandler(us service.UserService) *Handler {
	return &Handler{
		userService: us,
	}
}

func RegisterRoutes(h *Handler, jwtSecret string) *chi.Mux {
	r := chi.NewRouter()
	r.Use(middleware.LoggerMiddleware)

	r.Get("/swagger/*", httpSwagger.WrapHandler)

	r.Route("/api/v1", func(r chi.Router) {

		r.Post("/users", h.Create)
		r.Post("/login", h.Login)
		r.Get("/users/{id}", h.GetUserByID)
		r.Get("/users", h.GetUsers)

		r.Group(func(r chi.Router) {
			//r.Use(middleware.BasicAuthMiddleware(h.userService.Authenticate))
			r.Use(middleware.AuthMidleware(jwtSecret))

			r.Put("/users/{id}", h.Update)
			r.Delete("/users/{id}", h.Delete)

			r.Post("/users/{id}/vote", h.Vote)

		})
	})
	return r
}

// Login
// @Summary User Login
// @Description Login and get JWT token
// @Tags users
// @Accept json
// @Produce json
// @Param input body models.LoginRequest true "Login credentials"
// @Success 200 {object} models.LoginResponse
// @Failure 401 {object} handlers.JSONError "Invalid credentials"
// @Router /login [post]
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req models.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), ctxWithTimeout)
	defer cancel()
	slogger.Log.DebugContext(ctx, "Login request", "req", req)

	token, err := h.userService.Login(ctx, req)
	slogger.Log.DebugContext(ctx, "Login response", "token", token)
	if err != nil {
		if errors.Is(err, models.ErrInvalidCredentials) {
			WriteError(w, http.StatusUnauthorized, "Invalid email or password")
			return
		}
		WriteError(w, http.StatusInternalServerError, "Internal server error")
		slogger.Log.ErrorContext(ctx, "Login failed", "err", err)
		return
	}

	JSONResponse(w, http.StatusOK, models.LoginResponse{Token: token})
}

// Create creates a new user
// @Summary Create a new user
// @Description Register a new user in the system
// @Tags users
// @Accept json
// @Produce json
// @Param input body models.CreateUserRequest true "User registration info"
// @Success 201 {object} models.UserResponse
// @Failure 400 {object} handlers.JSONError "Invalid input or validation info"
// @Failure 409 {object} handlers.JSONError "User already exists"
// @Failure 500 {object} handlers.JSONError "Internal server error"
// @Router /users [post]
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {

	var req models.CreateUserRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "Invalid request body")
		slogger.Log.ErrorContext(r.Context(), "Invalid request body", "err", err)
		return
	}

	if req.Email == "" || req.Password == "" || req.FirstName == "" || req.LastName == "" {
		WriteError(w, http.StatusBadRequest, "Fields cannot be empty")
		return
	}
	if err := utils.ValidatePassword(req.Password); err != nil {
		WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), ctxWithTimeout)
	defer cancel()

	slogger.Log.DebugContext(ctx, "Creating user",
		"email", req.Email,
		"firstName", req.FirstName,
		"lastName", req.LastName,
	)

	createdUser, err := h.userService.Create(ctx, req)
	if err != nil {
		switch {
		case errors.Is(err, models.ErrUserAlreadyExists):
			WriteError(w, http.StatusConflict, "User already exists")
			return
		}
		WriteError(w, http.StatusInternalServerError, err.Error())
		slogger.Log.ErrorContext(ctx, "Failed to create user", "err", err)
		return
	}

	JSONResponse(w, http.StatusCreated, createdUser)
}

// GetUserByID Get User By ID
// @Summary Get user by ID
// @Description Get User By ID from DB
// @Tags users
// @Accept json
// @Produce json
// @Param id path string true "User UUID" format(uuid)
// @Success 200 {object} models.UserResponse
// @Failure 400 {object} handlers.JSONError "Invalid UUID"
// @Failure 404 {object} handlers.JSONError "User not found"
// @Failure 500 {object} handlers.JSONError "Internal server error"
// @Router /users/{id} [get]
func (h *Handler) GetUserByID(w http.ResponseWriter, r *http.Request) {

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		WriteError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), ctxWithTimeout)
	defer cancel()

	user, err := h.userService.GetUserByID(ctx, id)
	if err != nil {
		switch {
		case errors.Is(err, models.ErrUserNotFound):
			WriteError(w, http.StatusNotFound, "User not found")
			slogger.Log.DebugContext(ctx, "User not found", "err", err, "id", id)
			return
		default:
			WriteError(w, http.StatusInternalServerError, "Failed to get user")
			slogger.Log.ErrorContext(ctx, "Failed to get user", "err", err)
			return
		}
	}
	JSONResponse(w, http.StatusOK, user)
}

// GetUsers Get list of users
// @Summary Get list of users
// @Description Get list of all users from DB
// @Tags users
// @Accept json
// @Produce json
// @Param limit query int false "Limit records per page (default 10)"
// @Param page query int false "Page number (default 1)"
// @Param order query string false "Sort order: asc or desc (default desc)"
// @Success 200 {object} models.ListOfUsersResponse
// @Failure 500 {object} handlers.JSONError "Failed to get users"
// @Router /users [get]
func (h *Handler) GetUsers(w http.ResponseWriter, r *http.Request) {

	var (
		limit uint64 = 10
		page  uint64 = 1
	)

	if s := r.URL.Query().Get("limit"); s != "" {
		l, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			WriteError(w, http.StatusBadRequest, "Invalid limit")
			return
		}
		limit = l
	}

	if s := r.URL.Query().Get("page"); s != "" {
		p, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			WriteError(w, http.StatusBadRequest, "Invalid page")
			return
		}
		page = p
	}

	order := r.URL.Query().Get("order")
	if order != "asc" {
		order = "desc"
	}

	ctx, cancel := context.WithTimeout(r.Context(), ctxWithTimeout)
	defer cancel()

	users, err := h.userService.GetUsers(ctx, limit, page, order)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "Failed to get users")
		slogger.Log.ErrorContext(ctx, "Failed to get users", "err", err)
		return
	}
	JSONResponse(w, http.StatusOK, users)
}

// Delete User delete by ID
// @Summary Delete user by ID
// @Description Delete user by ID from DB
// @Tags users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "User UUID" format(uuid)
// @Success 200 {object} nil
// @Failure 400 {object} handlers.JSONError "Invalid user ID"
// @Failure 403 {object} handlers.JSONError "You can delete only your own account"
// @Failure 500 {object} handlers.JSONError "Failed to delete user"
// @Router /users/{id} [delete]
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	targetID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		WriteError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}
	target, err := h.userService.GetUserByID(r.Context(), targetID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "Failed to get user")
		slogger.Log.ErrorContext(r.Context(), "Failed to get user", "err", err)
		return
	}
	requester := r.Context().Value(middleware.UserCtxKey{}).(*models.User)

	ctx, cancel := context.WithTimeout(r.Context(), ctxWithTimeout)
	defer cancel()
	if !PermissionCheck(requester, target) {
		WriteError(w, http.StatusForbidden, models.ErrPermissionDenied.Error())
		return
	}
	err = h.userService.Delete(ctx, targetID)
	if err != nil {
		switch {
		case errors.Is(err, models.ErrUserNotFound):
			WriteError(w, http.StatusNotFound, "User not found")
			return
		case errors.Is(err, models.ErrPermissionDenied):
			WriteError(w, http.StatusForbidden, models.ErrPermissionDenied.Error())
			return

		}
		WriteError(w, http.StatusInternalServerError, "Failed to delete user")
		slogger.Log.ErrorContext(ctx, "Failed to delete user", "err", err)
		return
	}

	JSONResponse(w, http.StatusOK, nil)
}

// Update User update by ID
// @Summary Update user by ID
// @Description Update user information by its UUID
// @Tags users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "User UUID" format(uuid)
// @Param input body models.UpdateUserRequest true "User update info"
// @Success 200 {object} models.UserResponse "Successfully updated"
// @Failure 400 {object} handlers.JSONError "Invalid user ID"
// @Failure 403 {object} handlers.JSONError "Permission denied"
// @Failure 500 {object} handlers.JSONError "Failed to update user"
// @Router /users/{id} [put]
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {

	targetID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		WriteError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}

	requester := r.Context().Value(middleware.UserCtxKey{}).(*models.User)
	slogger.Log.DebugContext(r.Context(), "Updating user", "targetID", targetID, "requester", requester)

	target, err := h.userService.GetUserByID(r.Context(), targetID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "Failed to get user")
		slogger.Log.ErrorContext(r.Context(), "Failed to get user", "err", err)
		return
	}

	if !PermissionCheck(requester, target) {
		WriteError(w, http.StatusForbidden, models.ErrPermissionDenied.Error())
		return
	}

	var req models.UpdateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "Invalid request body")
		slogger.Log.ErrorContext(r.Context(), "Invalid request body", "err", err)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), ctxWithTimeout)
	defer cancel()

	if req.Role != nil && requester.Role != models.RoleAdmin {
		WriteError(w, http.StatusBadRequest, models.ErrPermissionDenied.Error())
		return
	}
	if req.Password != nil {
		if err := utils.ValidatePassword(*req.Password); err != nil {
			WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	updatedUser, err := h.userService.Update(ctx, targetID, req)
	if err != nil {
		switch {
		case errors.Is(err, models.ErrUserNotFound):
			WriteError(w, http.StatusNotFound, "User not found")
			return
		}
		WriteError(w, http.StatusInternalServerError, "Failed to update user")
		slogger.Log.ErrorContext(ctx, "Failed to update user", "err", err)
		return
	}

	JSONResponse(w, http.StatusOK, updatedUser)
}

func PermissionCheck(requester *models.User, target *models.UserResponse) bool {
	if requester.Role == models.RoleAdmin {
		return true
	}
	if requester.ID.String() == target.ID {
		return true
	}
	if requester.Role == models.RoleModerator {
		if target.Role != string(models.RoleUser) {
			return false
		}
		return true
	}
	return false
}

// Vote godoc
// @Summary Vote for a user
// @Description Vote +1 or -1 for a user profile, or 0 to withdraw. Limit: 1 vote per minute.
// @Tags users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Target User UUID" format(uuid)
// @Param input body models.VoteRequest true "Vote value (-1, 0, 1)"
// @Success 200 {object} models.UserResponse
// @Failure 400 {object} handlers.JSONError "Self voting not allowed / Invalid input"
// @Failure 429 {object} handlers.JSONError "Rate limit exceeded"
// @Router /users/{id}/vote [post]
func (h *Handler) Vote(w http.ResponseWriter, r *http.Request) {
	var (
		req models.VoteRequest
		err error
	)
	if req.TargetID, err = uuid.Parse(chi.URLParam(r, "id")); err != nil {
		WriteError(w, http.StatusBadRequest, "Invalid user ID")
		return
	}
	requester := r.Context().Value(middleware.UserCtxKey{}).(*models.User)

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Value != -1 && req.Value != 0 && req.Value != 1 {
		WriteError(w, http.StatusBadRequest, "Invalid value")
		return
	}

	updatedTargetUser, err := h.userService.VoteUser(r.Context(), requester.ID, req)
	if err != nil {
		switch {
		case errors.Is(err, models.ErrSelfVoting):
			WriteError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, models.ErrVoteTooOften):
			WriteError(w, http.StatusTooManyRequests, err.Error())
		case errors.Is(err, models.ErrUserNotFound):
			WriteError(w, http.StatusNotFound, "User not found")
		default:
			slogger.Log.ErrorContext(r.Context(), "Failed to vote user", "err", err)
			WriteError(w, http.StatusInternalServerError, "Failed to vote user")
		}
		return
	}
	JSONResponse(w, http.StatusOK, updatedTargetUser)
}
