package mongodb

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type Config struct {
	URI            string
	Db             string
	ConnectTimeout time.Duration
}

func NewMongoDbConn(ctx context.Context, cfg Config) (*mongo.Client, error) {
	client, err := mongo.Connect(context.Background(),
		options.Client().ApplyURI(cfg.URI).
			SetConnectTimeout(cfg.ConnectTimeout))
	if err != nil {
		return nil, err
	}

	if err := client.Ping(ctx, nil); err != nil {
		return nil, err
	}

	return client, err
}
