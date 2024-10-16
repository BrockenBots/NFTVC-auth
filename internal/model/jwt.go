package model

import "time"

type AccountClaims struct {
	jti           string
	tokenType     TokenType
	iat           uint64
	exp           uint64
	sub           string
	walletAddress string
	deviceId      string
	iss           string
	role          string
}

type Token struct {
	Id        string
	DeviceId  string
	AccountId string
	Token     string
	TokenType TokenType
	Exp       time.Duration
}

type TokenType string

var (
	accessToken  TokenType = "accessToken"
	refreshToken TokenType = "refreshToken"
)
