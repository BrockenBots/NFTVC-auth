package main

import (
	"log"
	"nftvc-auth/config"
	"nftvc-auth/logger"
	"nftvc-auth/server"
)

const pathToConfig = ""

func main() {
	cfg, err := config.LoadConfig(pathToConfig)
	if err != nil {
		log.Fatal("Failed to load config")
	}
	appLogger := logger.NewAppLogger(cfg.Logger)
	appLogger.InitLogger()
	appLogger.Fatal(server.NewServer(appLogger, cfg).Run())
}
