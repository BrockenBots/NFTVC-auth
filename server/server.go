package server

import (
	"nftvc-auth/config"
	"nftvc-auth/logger"
)

type server struct {
	log logger.Logger
	cfg *config.Config
}

func NewServer(log logger.Logger, cfg *config.Config) *server {
	return &server{
		log: log,
		cfg: cfg,
	}
}

func (s *server) Run() error {
	return nil
}
