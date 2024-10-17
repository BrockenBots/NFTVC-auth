package server

import (
	"context"
	"strings"
)

// const (
// 	createAccountsTableQuery = `
// 		CREATE TABLE IF NOT EXISTS accounts (
// 			id VARCHAR(255) PRIMARY KEY,
// 			wallet_pub VARCHAR(255) NOT NULL,
// 			wallet_verified BOOLEAN DEFAULT false,
// 			role VARCHAR(50) NOT NULL
// 		);
// 	`
// )

// func (s *server) InitPostgresTable(db *pgx.Conn) error {
// 	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
// 	defer cancel()

// 	_, err := db.Exec(ctx, createAccountsTableQuery)
// 	if err != nil {
// 		s.log.Fatalf("Failed to create accounts table: %v\n", err)
// 	}

// 	return nil
// }

func (s *server) initMongoDBCollections(ctx context.Context) {
	err := s.mongoClient.Database(s.cfg.Mongo.Db).CreateCollection(ctx, s.cfg.MongoCollections.Accounts)
	if err != nil {
		if !strings.Contains(err.Error(), "already exists") {
			s.log.Fatalf("(CreateCollection) err: %v", err)
		}
	}
	err = s.mongoClient.Database(s.cfg.Mongo.Db).CreateCollection(ctx, s.cfg.MongoCollections.RefreshTokens)
	if err != nil {
		if !strings.Contains(err.Error(), "already exists") {
			s.log.Fatalf("(CreateCollection) err: %v", err)
		}
	}
}
