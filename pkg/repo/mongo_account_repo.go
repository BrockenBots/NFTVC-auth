package repo

import (
	"context"
	"nftvc-auth/internal/model"
	"nftvc-auth/pkg/config"
	"nftvc-auth/pkg/logger"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type MongoAccountRepo struct {
	// repository.AccountRepository
	log logger.Logger
	cfg *config.Config
	db  *mongo.Client
}

func NewMongoAccountRepo(log logger.Logger, cfg *config.Config, db *mongo.Client) *MongoAccountRepo {
	return &MongoAccountRepo{log: log, cfg: cfg, db: db}
}

func (m *MongoAccountRepo) Add(ctx context.Context, account *model.Account) error {
	_, err := m.getAccountCollections().InsertOne(ctx, account, &options.InsertOneOptions{})
	if err != nil {
		m.log.Debugf("(MongoAccountRepo) error: %v", err)
		return err
	}
	return nil
}

func (m *MongoAccountRepo) Update(ctx context.Context, account *model.Account) error {
	ops := options.FindOneAndUpdate()
	ops.SetReturnDocument(options.After)
	ops.SetUpsert(false)

	if err := m.getAccountCollections().FindOneAndUpdate(ctx, bson.M{"_id": account.Id}, bson.M{"$set": account}, ops).Err(); err != nil {
		return err
	}

	return nil
}

func (m *MongoAccountRepo) GetById(ctx context.Context, accountId string) (*model.Account, error) {
	var account model.Account
	if err := m.getAccountCollections().FindOne(ctx, bson.M{"userId": accountId}).Decode(&account); err != nil {
		return nil, err
	}

	return &account, nil
}

func (m *MongoAccountRepo) GetByWalletAddress(ctx context.Context, walletPub string) (*model.Account, error) {
	var account model.Account
	if err := m.getAccountCollections().FindOne(ctx, bson.M{"wallet_pub": walletPub}).Decode(&account); err != nil {
		return nil, err
	}

	return &account, nil
}

func (m *MongoAccountRepo) getAccountCollections() *mongo.Collection {
	return m.db.Database(m.cfg.Mongo.Db).Collection(m.cfg.MongoCollections.Accounts)
}
