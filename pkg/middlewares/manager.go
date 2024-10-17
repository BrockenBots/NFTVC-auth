package middlewares

import (
	"context"
	"net/http"
	"nftvc-auth/pkg/config"
	"nftvc-auth/pkg/jwt"
	"nftvc-auth/pkg/logger"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type MiddlewareManager struct {
	log        logger.Logger
	cfg        *config.Config
	jwtManager jwt.JwtManager
}

func NewMiddlewareManager(log logger.Logger, cfg *config.Config) *MiddlewareManager {
	return &MiddlewareManager{log: log, cfg: cfg}
}

func (m *MiddlewareManager) CORS() echo.MiddlewareFunc {
	corsConfig := middleware.CORSConfig{
		AllowOrigins: []string{"*"}, // Пока так
		AllowMethods: []string{echo.GET, echo.POST, echo.OPTIONS},
		AllowHeaders: []string{"Content-Type", "Authorization"},
	}

	return middleware.CORSWithConfig(corsConfig)
}

func (m *MiddlewareManager) AuthMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		accessToken := strings.TrimPrefix(c.Request().Header.Get("Authorization"), "Bearer ")
		if accessToken == "" {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Missing or invalid token"})
		}

		claims, err := m.jwtManager.VerifyToken(context.Background(), accessToken)
		if err != nil {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Missing or invalid token"})
		}

		sub := claims["sub"].(string)
		deviceId := claims["device_id"].(string)
		revoked := m.jwtManager.IsRevokedToken(context.Background(), sub, deviceId, accessToken)
		if revoked {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Token is invalid"})
		}

		return next(c)
	}
}
