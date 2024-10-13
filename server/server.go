package server

import (
	"context"
	"nftvc-auth/config"
	"nftvc-auth/logger"
	"os"
	"os/signal"
	"syscall"

	echo "github.com/labstack/echo/v4"
)

type server struct {
	log  logger.Logger
	cfg  *config.Config
	echo *echo.Echo
}

func NewServer(log logger.Logger, cfg *config.Config) *server {
	return &server{
		log:  log,
		cfg:  cfg,
		echo: echo.New(),
	}
}

func (s *server) Run() error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	go func() {
		if err := s.runHttpServer(); err != nil {
			s.log.Error("(HttpServer) err: %v", err)
			cancel()
		}
	}()

	<-ctx.Done()
	return nil
}
