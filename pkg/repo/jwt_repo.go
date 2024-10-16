package repo

import (
	"context"
	"fmt"

	"nftvc-auth/internal/model"
	"nftvc-auth/pkg/logger"
	"time"

	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/mongo"
)

type JwtRepo struct {
	// repository.JwtRepository
	log         logger.Logger
	redisClient *redis.Client
	mongoClient *mongo.Collection
}

func (j *JwtRepo) SaveAccessToken(token model.Token) error {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	if err := j.redisClient.Set(ctx, fmt.Sprintf("active_token:%s:%s", token.AccountId, token.DeviceId), token.Token, token.Exp); err != nil {
		cancel()
		j.log.Debugf("(SaveTokens) Failed to save: %v", err)
		return fmt.Errorf("failed to save access token")
	}

	return nil
}

func (j *JwtRepo) SaveRefreshToken(token model.Token) error {
	// ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	// defer cancel()

	// if err := j.mongoClient.InsertOne()
	return nil
}

func (j *JwtRepo) RevokeTokens(accountId string, deviceId string) error {
	return nil
}

func (j *JwtRepo) ExistTokenInBlacklist(token string) bool {
	return false
}

func (j *JwtRepo) IsActiveAccessToken(token string) bool {
	return false
}
