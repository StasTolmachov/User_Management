package server

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"foxminded/4_user_management/internal/cache"
	"foxminded/4_user_management/internal/config"
	"foxminded/4_user_management/internal/handlers"
	"foxminded/4_user_management/internal/repository"
	"foxminded/4_user_management/internal/service"
	"foxminded/4_user_management/slogger"
)

func Run(cfg config.Config) {

	db, err := repository.NewPostgres(cfg.DB)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	repo := repository.NewUserRepo(db)
	redisClient, err := cache.NewRedisClient(cfg.Redis)
	if err != nil {
		slogger.Log.Warn("Failed to init Redis:", "err", err)
	}
	defer redisClient.Close()
	userService := service.NewUserService(repo, cfg.JWT, redisClient)

	ctxBG := context.Background()
	if err := userService.SyncAdmin(ctxBG, cfg.Admin); err != nil {
		log.Fatal("Failed to sync admin user:", err)
	}

	userHandler := handlers.NewHandler(userService)

	router := handlers.RegisterRoutes(userHandler, cfg.JWT.Secret)

	srv := &http.Server{
		Addr:         ":" + cfg.Api.Port,
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		slogger.Log.Info("Listening on port", "port", cfg.Api.Port)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("listen: %s\n", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	<-stop
	log.Println("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown:", err)
	}
	log.Println("Server exiting gracefully")

}
