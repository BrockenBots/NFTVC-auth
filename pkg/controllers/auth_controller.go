package controllers

import (
	"context"
	"fmt"
	"net/http"
	"nftvc-auth/internal/model"
	"nftvc-auth/internal/repository"
	"nftvc-auth/pkg/config"
	"nftvc-auth/pkg/jwt"
	"nftvc-auth/pkg/logger"
	"nftvc-auth/pkg/nonce"
	"nftvc-auth/pkg/requests"

	"github.com/go-playground/validator/v10"
	"github.com/gofrs/uuid"
	jwt5 "github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

type AuthController struct {
	log          logger.Logger
	cfg          *config.Config
	accountRepo  repository.AccountRepository
	validate     *validator.Validate
	nonceManager nonce.NonceManager
	jwtManager   jwt.JwtManager
}

func NewAuthController(log logger.Logger, cfg *config.Config, accountRepo repository.AccountRepository, nonceManager nonce.NonceManager, validator *validator.Validate, jwtManager jwt.JwtManager) *AuthController {
	return &AuthController{log: log, cfg: cfg, accountRepo: accountRepo, nonceManager: nonceManager, validate: validator, jwtManager: jwtManager}
}

// SignInWithWallet godoc
// @Summary Авторизация через кошелек
// @Description Авторизация пользователя с использованием его Ethereum кошелька
// @Tags auth
// @Accept  json
// @Produce  json
// @Param   signInWithWallet body requests.SignInWithWalletRequest true "SignInWithWallet Request"
// @Success 200 {object} response.SignInWithWalletResponse "Сгенерированный uuid для проверки подписи (nonce)"
// @Failure 400 {object} response.ErrorResponse "Ошибка валидации или неправильный запрос"
// @Failure 500 {object} response.ErrorResponse "Внутренняя ошибка сервера"
// @Router /api/auth/sign-in [post]
func (a *AuthController) SignInWithWallet(ctx echo.Context) error {
	a.log.Infof("(AuthController.SignInWithWallet)")
	var req requests.SignInWithWalletRequest
	if err := a.decodeRequest(ctx, &req); err != nil {
		a.log.Debugf("Failed to decode request SignInWithWallet: %v", err)
		return ctx.JSON(http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("Validation error: %v", err)})
	}

	nonce, err := a.nonceManager.GenerateNonce(req.WalletPub)
	if err != nil {
		a.log.Error("(SignInWithWallet) [GenerateNonce] err: ", err)
		return ctx.JSON(http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("Internal server error: %v", err)})
	}

	return ctx.JSON(http.StatusOK, map[string]string{"nonce": nonce})
}

// VerifySignature godoc
// @Summary Верификация подписи
// @Description Проверка подписи с использованием публичного ключа
// @Tags auth
// @Accept  json
// @Produce  json
// @Param   verifySignature body requests.VerifySignatureRequest true "VerifySignature Request"
// @Success 200 {object} response.VerifySignatureResponse "Подпись успешно проверена"
// @Failure 400 {object} response.ErrorResponse "Неверная подпись или неправильный запрос"
// @Failure 500 {object} response.ErrorResponse "Внутренняя ошибка сервера"
// @Router /api/auth/verify-signature [post]
func (a *AuthController) VerifySignature(ctx echo.Context) error {
	a.log.Infof("(AuthController.VerifySignature)")
	var req requests.VerifySignatureRequest
	if err := a.decodeRequest(ctx, &req); err != nil {
		a.log.Debugf("Failed to decode request VerifySignatureRequest: %v", err)
		return ctx.JSON(http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("Validation error: %v", err)})
	}

	nonce, err := a.nonceManager.GetNonce(req.WalletPub)
	if err != nil {
		a.log.Debugf("(AuthController.VerifySignature.GetNonce) error: %v", err)
		return ctx.JSON(http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("Internal server error: %v", err)})
	}

	var account *model.Account
	account, _ = a.accountRepo.GetByWalletAddress(context.Background(), req.WalletPub)
	if account == nil {
		accountUuid, _ := uuid.NewV7()
		accountId := accountUuid.String()

		account = model.NewAccount(accountId, req.WalletPub, "user")
		if err := a.accountRepo.Add(context.Background(), account); err != nil {
			a.log.Error("(SignInWithWallet) [AccountRepository.Add] err: ", err)
			return ctx.JSON(http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("Internal server error: %v", err)})
		}
	}

	if ok := a.verifySig(nonce.WalletAddress, req.Signature, []byte(nonce.Nonce)); !ok {
		return ctx.JSON(http.StatusBadRequest, map[string]string{"error": "signature and public key are not suitable"})
	}

	if err := a.nonceManager.DeleteNonce(nonce.WalletAddress); err != nil {
		a.log.Debugf("Failed to delete nonce: %v", err)
	}

	deviceUuid, _ := uuid.NewV7()
	deviceId := deviceUuid.String()
	accessToken, refreshToken, err := a.jwtManager.GenerateTokens(context.Background(), account.Id, deviceId, account.WalletPub, account.Role)
	if err != nil {
		a.log.Debugf("(GenerateTokens) Failed to generate tokens: %v", err)
		return ctx.JSON(http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("Internal server error: %v", err)})
	}

	return ctx.JSON(http.StatusOK, map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}

// RefreshTokens godoc
// @Summary Обновление Access и Refresh токенов
// @Description Обновление access и refresh токенов с использованием валидного refresh токена
// @Tags auth
// @Accept  json
// @Produce  json
// @Param   refreshTokens body requests.RefreshTokensRequest true "RefreshTokens Request"
// @Success 200 {object} response.RefreshTokensResponse "Новые access и refresh токены"
// @Failure 400 {object} response.ErrorResponse "Неверный refresh токен или ошибка валидации"
// @Failure 500 {object} response.ErrorResponse "Внутренняя ошибка сервера"
// @Router /api/auth/refresh-tokens [post]
func (a *AuthController) RefreshTokens(ctx echo.Context) error {
	a.log.Infof("(AuthController.RefreshTokens)")
	var req requests.RefreshTokensRequest
	if err := a.decodeRequest(ctx, &req); err != nil {
		a.log.Debugf("Failed to validate request RefreshTokens: %v", err)
		return ctx.JSON(http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("Validation error: %v", err)})
	}

	accessToken, refreshToken, err := a.jwtManager.RefreshToken(context.Background(), req.RefreshToken)
	if err != nil {
		a.log.Debugf("(RefreshTokens) error: %v", err)
		return ctx.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	return ctx.JSON(http.StatusOK, map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}

// RefreshTokens godoc
// @Summary Обновление Access и Refresh токенов
// @Description Обновление access и refresh токенов с использованием валидного refresh токена
// @Tags auth
// @Accept  json
// @Produce  json
// @Param   refreshTokens body requests.SignOutRequest true "RefreshTokens Request"
// @Success 200 {object} response.SignOutResponse "Пустой ответ при успешном выходе"
// @Failure 400 {object} response.ErrorResponse "При неверных токенах доступа"
// @Failure 500 {object} response.ErrorResponse "Внутренняя ошибка сервера"
// @Router /api/auth/refresh-tokens [post]
func (a *AuthController) SignOut(ctx echo.Context) error {
	var req requests.SignOutRequest
	if err := a.decodeRequest(ctx, &req); err != nil {
		a.log.Debugf("Failed to validate SignOutRequest: %v", err)
		return ctx.JSON(http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("Validation error: %v", err)})
	}

	accountClaims := (ctx.Get("claims")).(jwt5.MapClaims)
	token := ctx.Get("token").(string)

	accountId := accountClaims["sub"].(string)
	deviceId := accountClaims["device_id"].(string)

	err := a.jwtManager.RevokeTokens(context.Background(), accountId, deviceId, token)
	if err != nil {
		a.log.Debugf("(SignOut) error by revoking tokens: %v")
		return ctx.JSON(http.StatusInternalServerError, map[string]string{"error": "Error by revoking tokens"})
	}

	return ctx.JSON(http.StatusOK, map[string]string{})
}

func (a *AuthController) VerifyToken(ctx echo.Context) error {
	a.log.Debugf("VerifyToken")
	var req requests.VerifyTokenRequest
	if err := a.decodeRequest(ctx, &req); err != nil {
		a.log.Debugf("Failed to validate VerifyToken: %v", err)
		return ctx.JSON(http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("Validation error: %v", err)})
	}

	mapClaims, err := a.jwtManager.VerifyToken(context.Background(), req.AccessToken)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("Failed to verify token: %v", err)})
	}

	sub := mapClaims["sub"].(string)

	return ctx.JSON(http.StatusOK, map[string]string{
		"account_id": sub,
	})
}

func (a *AuthController) ChangeRole(ctx echo.Context) error {
	var req requests.ChangeRoleRequest
	if err := a.decodeRequest(ctx, &req); err != nil {
		a.log.Debugf("Failed to validate ChangeRole: %v", err)
		return ctx.JSON(http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("Validation error: %v", err)})
	}

	accountClaims := (ctx.Get("claims")).(jwt5.MapClaims)
	accountId := accountClaims["sub"].(string)
	deviceId := accountClaims["device_id"].(string)

	account := &model.Account{Id: accountId, Role: req.Role}
	if err := a.accountRepo.Update(context.Background(), account); err != nil {
		return ctx.JSON(http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("Error by update role: %v", err)})
	}

	oldRefreshToken, err := a.jwtManager.GetRefreshToken(context.Background(), accountId, deviceId)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("Error by get token: %v", err)})
	}

	accessToken, refreshToken, err := a.jwtManager.RefreshToken(context.Background(), oldRefreshToken)
	if err != nil {
		a.log.Debugf("(RefreshTokens) error: %v", err)
		return ctx.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	return ctx.JSON(http.StatusOK, map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}
