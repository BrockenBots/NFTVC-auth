package server

import (
	_ "nftvc-auth/docs"

	echoSwagger "github.com/swaggo/echo-swagger"
)

func (s *server) runHttpServer() error {
	s.echo.Use(s.middleware.CORS())

	s.mapRoutes()

	return s.echo.Start(s.cfg.Http.Port)
}

func (s *server) mapRoutes() {
	s.echo.POST("api/auth/sign-in", s.authController.SignInWithWallet)
	s.echo.POST("api/auth/verify-signature", s.authController.VerifySignature)
	s.echo.POST("api/auth/refresh-tokens", s.authController.RefreshTokens)

	authGroup := s.echo.Group("api/auth", s.middleware.AuthMiddleware)
	authGroup.POST("/sign-out", s.authController.SignOut)
	authGroup.POST("/change-role", s.authController.ChangeRole)

	s.echo.POST("api/auth/verify-token", s.authController.VerifyToken)

	s.echo.GET("/swagger/*", echoSwagger.WrapHandler)
}
