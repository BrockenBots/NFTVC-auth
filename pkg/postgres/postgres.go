package postgres

import (
	"context"
	"fmt"
	"nftvc-auth/pkg/logger"

	"github.com/jackc/pgx/v5"
)

type PostgresConfig struct {
	ConnectionString string `mapstructure:"connectionString"`
	Db               string `mapstructure:"db"`
}

type PostgresConnector struct {
	log logger.Logger
	cfg *PostgresConfig
}

func NewPostgres(log logger.Logger, cfg *PostgresConfig) *PostgresConnector {
	return &PostgresConnector{log: log, cfg: cfg}
}

func (p *PostgresConnector) NewPostgresConn(ctx context.Context) (*pgx.Conn, error) {
	conn, err := pgx.Connect(ctx, p.cfg.ConnectionString)
	if err != nil {
		p.log.Error("(Postgres) error: ", err)
		return nil, fmt.Errorf("failed to connect with postgres")
	}

	if err := conn.Ping(ctx); err != nil {
		p.log.Error("(Postgres) error: ", err)
		return nil, fmt.Errorf("failed to ping: %v", err)
	}

	return conn, nil
}
