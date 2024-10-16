package server

import (
	_ "nftvc-auth/docs"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	echoSwagger "github.com/swaggo/echo-swagger"
)

func (s *server) runHttpServer() error {
	corsConfig := middleware.CORSConfig{
		AllowOrigins: []string{"*"}, // Пока так
		AllowMethods: []string{echo.GET, echo.POST},
		AllowHeaders: []string{"Content-Type", "Authorization"},
	}

	s.echo.Use(middleware.CORSWithConfig(corsConfig))

	s.mapRoutes()

	return s.echo.Start(s.cfg.Http.Port)
}

func (s *server) mapRoutes() {
	s.echo.POST("api/auth/sign-in", s.authController.SignInWithWallet)
	s.echo.POST("api/auth/verify-signature", s.authController.VerifySignature)
	s.echo.POST("api/auth/sign-out", s.authController.SignOut)

	s.echo.GET("/swagger/*", echoSwagger.WrapHandler)
}
