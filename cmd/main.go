package main

import (
	"nftvc-auth/config"
	"nftvc-auth/logger"
	"nftvc-auth/server"
)

const pathToConfig = "config/config.yml"

func main() {
	cfg, err := config.LoadConfig(pathToConfig)
	if err != nil {
		panic("Failed to load config")
	}
	appLogger := logger.NewAppLogger(cfg.Logger)
	appLogger.InitLogger()
	appLogger.Fatal(server.NewServer(appLogger, cfg).Run())
}
