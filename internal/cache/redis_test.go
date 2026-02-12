package cache

import (
	"context"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"foxminded/4_user_management/internal/config"
)

type RedisSuite struct {
	suite.Suite
	container testcontainers.Container
	client    CacheRepository
}

func (s *RedisSuite) SetupSuite() {
	ctx := context.Background()

	req := testcontainers.ContainerRequest{
		Image:        "redis:7-alpine",
		ExposedPorts: []string{"6379/tcp"},
		WaitingFor:   wait.ForLog("Ready to accept connections"),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		s.T().Fatal("Cannot start redis container", err)
	}

	s.container = container

	host, err := container.Host(ctx)
	s.Require().NoError(err)

	mappedPort, err := container.MappedPort(ctx, "6379")
	s.Require().NoError(err)

	cfg := config.Redis{
		Host: host,
		Port: mappedPort.Port(),
		TTL:  time.Minute,
	}

	client, err := NewRedisClient(cfg)
	if err != nil {
		s.T().Fatal("Cannot connect to redis:", err)
	}
	s.client = client
}
func (s *RedisSuite) TearDownSuite() {
	if s.client != nil {
		_ = s.client.Close()
	}
	if s.container != nil {
		_ = s.container.Terminate(context.Background())
	}
}

func (s *RedisSuite) TestSetAndGet() {
	ctx := context.Background()
	key := "test_key"
	value := "test_value"

	err := s.client.Set(ctx, key, value)
	s.Require().NoError(err)

	val, err := s.client.Get(ctx, key)
	s.Require().NoError(err)
	s.Equal(value, val)
}

func (s *RedisSuite) TestDelete() {
	ctx := context.Background()
	key := "delete"
	value := "data_delete"

	err := s.client.Set(ctx, key, value)
	s.Require().NoError(err)

	err = s.client.Del(ctx, key)
	s.Require().NoError(err)

	_, err = s.client.Get(ctx, key)
	s.Error(err)
	s.Equal(redis.Nil, err)
}

func (s *RedisSuite) TestGet_NotFound() {
	ctx := context.Background()
	key := "not_exist"

	_, err := s.client.Get(ctx, key)
	s.Error(err)
	s.Equal(redis.Nil, err)
}

func (s *RedisSuite) TestTTL() {
	if testing.Short() {
		s.T().Skip("skipping ttl test in short mode")
	}

	ctx := context.Background()
	key := "short_lived_key"
	value := "data"

	host, err := s.container.Host(ctx)
	s.Require().NoError(err)

	mappedPort, err := s.container.MappedPort(ctx, "6379")
	s.Require().NoError(err)

	cfg := config.Redis{
		Host: host,
		Port: mappedPort.Port(),
		TTL:  time.Second,
	}

	client, err := NewRedisClient(cfg)
	if err != nil {
		s.T().Fatal("Cannot connect to redis:", err)
	}

	err = client.Set(ctx, key, value)
	s.Require().NoError(err)

	time.Sleep(cfg.TTL + 500*time.Millisecond)

	_, err = s.client.Get(ctx, key)
	s.Error(err, "Key should be expired")
	s.Equal(redis.Nil, err)
}

func TestRedisSuite(t *testing.T) {
	suite.Run(t, new(RedisSuite))
}
