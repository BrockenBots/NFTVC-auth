package server

func (s *server) runHttpServer() error {
	return s.echo.Start(s.cfg.Http.Port)
}
