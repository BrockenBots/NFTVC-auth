package server

import (
	"context"
	"nftvc-auth/pkg/config"
	"nftvc-auth/pkg/controllers"
	"nftvc-auth/pkg/logger"
	"nftvc-auth/pkg/nonce"
	"nftvc-auth/pkg/postgres"
	r "nftvc-auth/pkg/redis"
	"nftvc-auth/pkg/repo"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/go-playground/locales/en"
	ut "github.com/go-playground/universal-translator"
	"github.com/go-playground/validator/v10"
	en_translations "github.com/go-playground/validator/v10/translations/en"
	echo "github.com/labstack/echo/v4"
)

type server struct {
	log            logger.Logger
	cfg            *config.Config
	echo           *echo.Echo
	authController *controllers.AuthController
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

	postgresConnector := postgres.NewPostgres(s.log, s.cfg.Postgres)
	conn, err := postgresConnector.NewPostgresConn(ctx)
	if err != nil {
		return err
	}

	s.InitPostgresTable(conn)

	redisConnector := r.NewRedisConnector(s.log, s.cfg.Redis)
	redisClient, err := redisConnector.NewRedisConn(ctx)
	if err != nil {
		return err
	}

	accountRepo := repo.NewPostgresAccountRepo(s.log, conn)
	nonceRepo := repo.NewNonceRedisRepo(s.log, redisClient)
	nonceManager := nonce.NewNonceManager(s.log, s.cfg.Nonce, nonceRepo)

	validate := s.setupValidator()

	s.authController = controllers.NewAuthController(s.log, s.cfg, accountRepo, nonceManager, validate)

	go func() {
		if err := s.runHttpServer(); err != nil {
			s.log.Error("(HttpServer) err: %v", err)
			cancel()
		}
	}()

	<-ctx.Done()

	shutdownCtx, cancelShutdownCtx := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelShutdownCtx()

	s.log.Infof("Server shutdown...")

	if err := s.echo.Shutdown(shutdownCtx); err != nil {
		s.log.Infof("Shutdown server with error: %v", err)
		return err
	}

	s.log.Infof("Server shutdown succesfuly")

	return nil
}

func (s *server) setupValidator() *validator.Validate {
	validate := validator.New()

	validate.RegisterValidation("eth_addr", func(fl validator.FieldLevel) bool {
		addr := fl.Field().String()
		return common.IsHexAddress(addr)
	})

	en := en.New()
	uni := ut.New(en, en)

	trans, _ := uni.GetTranslator("en")
	en_translations.RegisterDefaultTranslations(validate, trans)
	validate.RegisterTranslation("eth_addr", trans, func(ut ut.Translator) error {
		return ut.Add("eth_addr", "{0} must be a valid Ethereum address", true)
	}, func(ut ut.Translator, fe validator.FieldError) string {
		t, _ := ut.T("eth_addr", fe.Field())
		return t
	})

	return validate
}
