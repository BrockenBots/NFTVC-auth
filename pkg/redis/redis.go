package redis

import (
	"context"
	"fmt"
	"nftvc-auth/pkg/logger"

	"github.com/redis/go-redis/v9"
)

type RedisConfig struct {
	Port string `mapstructure:"port"`
}

type RedisConnector struct {
	log logger.Logger
	cfg *RedisConfig
}

func NewRedisConnector(log logger.Logger, cfg *RedisConfig) *RedisConnector {
	return &RedisConnector{log: log, cfg: cfg}
}

func (r *RedisConnector) NewRedisConn(ctx context.Context) (*redis.Client, error) {
	rsc := redis.NewClient(&redis.Options{
		Addr: r.cfg.Port,
	})

	if err := rsc.Ping(ctx).Err(); err != nil {
		r.log.Error("(RedisConnector) error: ", err)
		return nil, fmt.Errorf("failed to ping redis: %v", err)
	}

	return rsc, nil
}
