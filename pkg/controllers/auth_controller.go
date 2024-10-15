package controllers

import (
	"fmt"
	"net/http"
	"nftvc-auth/internal/model"
	"nftvc-auth/internal/repository"
	"nftvc-auth/pkg/config"
	"nftvc-auth/pkg/logger"
	"nftvc-auth/pkg/nonce"
	"nftvc-auth/pkg/requests"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/go-playground/validator/v10"
	"github.com/gofrs/uuid"
	"github.com/labstack/echo/v4"
)

type AuthController struct {
	log          logger.Logger
	cfg          *config.Config
	accountRepo  repository.AccountRepository
	validate     *validator.Validate
	nonceManager nonce.NonceManager
}

func NewAuthController(log logger.Logger, cfg *config.Config, accountRepo repository.AccountRepository, nonceManager nonce.NonceManager, validator *validator.Validate) *AuthController {
	return &AuthController{log: log, cfg: cfg, accountRepo: accountRepo, nonceManager: nonceManager, validate: validator}
}

// SignInWithWallet godoc
// @Summary Авторизация через кошелек
// @Description Авторизация пользователя с использованием его Ethereum кошелька
// @Tags auth
// @Accept  json
// @Produce  json
// @Param   signInWithWallet body requests.SignInWithWalletRequest true "SignInWithWallet Request"
// @Success 200 {object} map[string]string "ID пользователя и nonce"
// @Failure 400 {object} map[string]string "Ошибка валидации или неправильный запрос"
// @Failure 500 {object} map[string]string "Внутренняя ошибка сервера"
// @Router /api/auth/sign-in [post]
func (a *AuthController) SignInWithWallet(ctx echo.Context) error {
	a.log.Debugf("(SignInWithWallet)")
	var req requests.SignInWithWalletRequest
	if err := ctx.Bind(&req); err != nil {
		return ctx.JSON(http.StatusBadGateway, map[string]string{"error": "Invalid request"})
	}

	if err := a.validate.Struct(req); err != nil {
		validationErrors := err.(validator.ValidationErrors)
		return ctx.JSON(http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("Validation error: %v", validationErrors)})
	}

	accountUuid, _ := uuid.NewV7()
	accountId := accountUuid.String()

	nonce, err := a.nonceManager.GenerateNonce(req.WalletPub)
	if err != nil {
		a.log.Error("(SignInWithWallet) [GenerateNonce] err: ", err)
		return ctx.JSON(http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("Internal server error: %v", err)})
	}

	account := model.NewAccount(accountId, req.WalletPub, "user")
	if err := a.accountRepo.Add(account); err != nil {
		a.log.Error("(SignInWithWallet) [AccountRepository.Add] err: ", err)
		return ctx.JSON(http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("Internal server error: %v", err)})
	}

	return ctx.JSON(http.StatusOK, map[string]string{"Id": accountId, "nonce": nonce})
}

// VerifySignature godoc
// @Summary Верификация подписи
// @Description Проверка подписи с использованием публичного ключа
// @Tags auth
// @Accept  json
// @Produce  json
// @Param   verifySignature body requests.VerifySignatureRequest true "VerifySignature Request"
// @Success 200 {object} map[string]string "Подпись успешно проверена"
// @Failure 400 {object} map[string]string "Неверная подпись или неправильный запрос"
// @Router /api/auth/verify-signature [post]
func (a *AuthController) VerifySignature(ctx echo.Context) error {
	var req requests.VerifySignatureRequest
	if err := ctx.Bind(&req); err != nil {
		return ctx.JSON(http.StatusBadGateway, map[string]string{"error": "Invalid request"})
	}

	if err := a.validate.Struct(req); err != nil {
		validationErrors := err.(validator.ValidationErrors)
		return ctx.JSON(http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("Validation error: %v", validationErrors)})
	}

	nonce, err := a.nonceManager.GetNonce(req.WalletPub)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("Internal server error: %v", err)})
	}

	res := a.verifySig(nonce.WalletAddress, req.Signature, []byte(nonce.Nonce))
	if !res {
		return ctx.JSON(http.StatusBadRequest, map[string]string{"error": "signature and public key are not suitable"})
	}

	return ctx.JSON(http.StatusOK, map[string]string{})
}

func (a *AuthController) verifySig(from, sigHex string, msg []byte) bool {
	sig, err := hexutil.Decode(sigHex)
	if err != nil {
		a.log.Debugf("Failed to decode signature: %v", err)
		return false
	}

	msg = accounts.TextHash(msg)

	if sig[crypto.RecoveryIDOffset] == 27 || sig[crypto.RecoveryIDOffset] == 28 {
		sig[crypto.RecoveryIDOffset] -= 27
	}

	recovered, err := crypto.SigToPub(msg, sig)
	if err != nil {
		return false
	}

	recoveredAddr := crypto.PubkeyToAddress(*recovered)
	return from == recoveredAddr.Hex()
}

func (a *AuthController) SignOut(ctx echo.Context) error {
	return nil
}
