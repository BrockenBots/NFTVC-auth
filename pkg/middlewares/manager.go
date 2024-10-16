package middlewares

import (
	"nftvc-auth/pkg/config"
	"nftvc-auth/pkg/logger"
)

type MiddlewareManager struct {
	log logger.Logger
	cfg *config.Config
}
