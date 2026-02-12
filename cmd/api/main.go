package main

import (
	"log"

	_ "foxminded/4_user_management/docs"

	"foxminded/4_user_management/internal/config"
	"foxminded/4_user_management/internal/server"
	"foxminded/4_user_management/slogger"
)

// @title User Management
// @version 1.0
// @host localhost:8080
// @BasePath /api/v1

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and your JWT token.
func main() {
	slogger.MakeLogger(true)

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Configuration load failed: %s", err)
	}
	slogger.Log.Debug("Config loaded", "config:", cfg)

	server.Run(*cfg)

}
