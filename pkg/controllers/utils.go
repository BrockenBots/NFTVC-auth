package controllers

import (
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
)

func (a *AuthController) verifySig(from, sigHex string, msg []byte) bool {
	sig, err := hexutil.Decode(sigHex)
	if err != nil {
		a.log.Debugf("Failed to decode signature: %v", err)
		return false
	}

	msg = accounts.TextHash(msg)

	if len(sig) != 65 {
		a.log.Debugf("Invalid signature length: %d", len(sig))
		return false
	}

	if sig[crypto.RecoveryIDOffset] == 27 || sig[crypto.RecoveryIDOffset] == 28 {
		sig[crypto.RecoveryIDOffset] -= 27
	}

	recovered, err := crypto.SigToPub(msg, sig)
	if err != nil {
		a.log.Debugf("Failed to recover public key from signature: %v", err)
		return false
	}

	recoveredAddr := crypto.PubkeyToAddress(*recovered)
	return strings.EqualFold(from, recoveredAddr.Hex())
}

func (a *AuthController) decodeRequest(ctx echo.Context, i interface{}) error {
	if err := ctx.Bind(i); err != nil {
		return fmt.Errorf("invalid request")
	}

	if err := a.validate.Struct(i); err != nil {
		return err.(validator.ValidationErrors)
	}

	return nil
}
