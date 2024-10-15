package server

func (s *server) runHttpServer() error {
	s.mapRoutes()

	return s.echo.Start(s.cfg.Http.Port)
}

func (s *server) mapRoutes() {

	s.echo.POST("api/auth/sign-in", s.authController.SignInWithWallet)
	s.echo.POST("api/auth/verify-signature", s.authController.VerifySignature)
	s.echo.POST("api/auth/sign-out", s.authController.SignOut)

}
