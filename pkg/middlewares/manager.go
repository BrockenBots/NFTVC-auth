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

func NewMiddlewareManager(log logger.Logger, cfg *config.Config, jwtManager jwt.JwtManager) *MiddlewareManager {
	return &MiddlewareManager{log: log, cfg: cfg, jwtManager: jwtManager}
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

		sub, ok := claims["sub"].(string)
		if !ok {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Token is invalid"})
		}
		deviceId, ok := claims["device_id"].(string)
		if !ok {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Token is invalid"})
		}
		tokenType, ok := claims["token_type"].(string)
		if !ok || tokenType != "access" {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Token is invalid"})
		}

		revoked := m.jwtManager.IsRevokedToken(context.Background(), sub, deviceId, accessToken)
		if revoked {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Token in blacklist"})
		}

		c.Set("claims", claims)
		c.Set("token", accessToken)

		return next(c)
	}
}
