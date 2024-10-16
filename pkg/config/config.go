package config

import (
	"fmt"
	"nftvc-auth/pkg/logger"
	"nftvc-auth/pkg/nonce"
	"nftvc-auth/pkg/postgres"
	redisConnector "nftvc-auth/pkg/redis"

	"github.com/spf13/viper"
)

type Config struct {
	Http             Http                        `mapstructure:"http" validate:"required"`
	Logger           *logger.Config              `mapstructure:"logger" validate:"required"`
	Postgres         *postgres.PostgresConfig    `mapstructure:"postgres" validate:"required"`
	Redis            *redisConnector.RedisConfig `mapstructure:"redis" validate:"required"`
	Nonce            *nonce.NonceConfig          `mapstructure:"nonce" validate:"required"`
	MongoCollections *MongoCollections           `mapstructure:"mongoCollections" validate:"required"`
}

type MongoCollections struct {
	Accounts      string `mapstructure:"accounts" validate:"required"`
	RefreshTokens string `mapstructure:"refreshTokens" validate:"required"`
}

type Http struct {
	Port string `mapstructure:"port" validate:"required"`
}

func LoadConfig(pathToConfig string) (*Config, error) {
	if pathToConfig == "" {
		return nil, fmt.Errorf("path to cfg is empty")
	}

	cfg := &Config{}

	viper.SetConfigType("yml")
	viper.SetConfigFile(pathToConfig)

	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("(ReadInConfig) error: %v", err)
	}

	if err := viper.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal cfg")
	}

	return cfg, nil
}
