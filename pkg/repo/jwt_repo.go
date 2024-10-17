package repo

import (
	"context"
	"fmt"
	"strings"

	"nftvc-auth/internal/model"
	"nftvc-auth/pkg/config"
	"nftvc-auth/pkg/logger"

	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type JwtRepo struct {
	// repository.JwtRepository
	log         logger.Logger
	cfg         *config.Config
	redisClient *redis.Client
	mongoClient *mongo.Client
}

func NewJwtRepo(log logger.Logger, cfg *config.Config, redisClient *redis.Client, mongoClient *mongo.Client) *JwtRepo {
	return &JwtRepo{log: log, cfg: cfg, redisClient: redisClient, mongoClient: mongoClient}
}

func (j *JwtRepo) SaveAccessToken(ctx context.Context, token *model.Token) error {
	if err := j.redisClient.Set(ctx, fmt.Sprintf("active_token:%s:%s", token.AccountId, token.DeviceId), token.Token, j.cfg.AccessTokenExp).Err(); err != nil {
		j.log.Debugf("(SaveTokens) Failed to save: %v", err)
		return fmt.Errorf("failed to save access token")
	}

	return nil
}

func (j *JwtRepo) SaveRefreshToken(ctx context.Context, token *model.Token) error {
	_, err := j.getTokensCollection().InsertOne(ctx, token, &options.InsertOneOptions{})
	if err != nil {
		return err
	}

	return nil
}

func (j *JwtRepo) RevokeTokens(ctx context.Context, accountId string, deviceId string, acceptedToken string) error {
	col := j.getTokensCollection()

	_, err := col.DeleteOne(ctx, bson.M{"accountId": accountId, "deviceId": deviceId})
	if err != nil {
		if strings.Contains(err.Error(), "no documents") {
			return err
		}

		return err
	}

	activeToken, err := j.GetAccessToken(ctx, accountId, deviceId)
	if err != nil {
		if err == redis.Nil {
			j.log.Debugf("No active token found for accountId: %s, deviceId: %s", accountId, deviceId)
			return j.addToBlacklist(ctx, accountId, deviceId, acceptedToken)
		} else {
			return fmt.Errorf("error retrieving active token: %v", err)
		}
	}

	err = j.addToBlacklist(ctx, accountId, deviceId, activeToken)
	if err != nil {
		return err
	}

	return nil
}

func (j *JwtRepo) addToBlacklist(ctx context.Context, accountId, deviceId string, token string) error {
	res := j.redisClient.Get(ctx, fmt.Sprintf("blacklist:%s:%s:%s", accountId, deviceId, token))
	if res.Err() != nil {
		j.redisClient.Set(ctx, fmt.Sprintf("blacklist:%s:%s:%s", accountId, deviceId, token), token, j.cfg.AccessTokenExp)
		return nil
	}

	return nil
}

func (j *JwtRepo) DeleteRefreshToken(ctx context.Context, jti string) error {
	_, err := j.getTokensCollection().DeleteOne(ctx, bson.M{"_id": jti})
	return err
}

func (j *JwtRepo) GetAccessToken(ctx context.Context, accountId string, deviceId string) (string, error) {
	res := j.redisClient.Get(ctx, fmt.Sprintf("active_token:%s:%s", accountId, deviceId))
	if err := res.Err(); err != nil {
		j.log.Debugf("Failed to find accessToken: %v", err)
		return "", err
	}

	return res.Val(), nil
}

func (j *JwtRepo) IsRevokedToken(ctx context.Context, accountId string, deviceId string, token string) bool {
	res := j.redisClient.Get(ctx, fmt.Sprintf("blacklist:%s:%s:%s", accountId, deviceId, token))
	if err := res.Err(); err != nil {
		return false
	}

	return true
}

func (j *JwtRepo) getTokensCollection() *mongo.Collection {
	return j.mongoClient.Database(j.cfg.Mongo.Db).Collection(j.cfg.MongoCollections.RefreshTokens)
}
