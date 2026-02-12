.PHONY: db-up db-down run docker-up docker-down migrate-up migrate-down lint cover mock swag

include .env
export $(shell sed 's/=.*//' .env)

DB_URL=postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@${POSTGRES_HOST}:${POSTGRES_PORT}/${POSTGRES_DB}?sslmode=disable

db-up:
	docker compose up -d db

db-down:
	docker compose down -v

run:
	go run cmd/api/main.go

docker-up:
	docker compose up -d --build

docker-down:
	docker compose down

migrate-up:
	migrate -path migrations -database "${DB_URL}" up

migrate-down:
	migrate -path migrations -database "${DB_URL}" down

lint:
	golangci-lint run

cover:
	@echo "Running tests with integration tags and filtering..."
	go test -tags integration -coverprofile=coverage.raw.out ./...
	cat coverage.raw.out | grep -v "_mock.go" | grep -v ".pb.go" | grep -v "server.go" | grep -v "slogger.go" | grep -v "docs.go" > coverage.out
	go tool cover -func=coverage.out
	@rm coverage.raw.out

mock:
	mockery --all

swag:
	swag init -g cmd/api/main.go