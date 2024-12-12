package token

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)


const minSecretKeySize = 32

// JWTMaker is a JSON Web Token maker
type JWTMaker struct {
	secretKey string
}

func NewJWTMaker(secretKey string) (Maker,error) {
	if len(secretKey) < minSecretKeySize {
		return nil,fmt.Errorf("invalid key size: must be at least %d characters",minSecretKeySize)
	}
	return &JWTMaker{secretKey},nil
}


// CreateToken creates a new token for a specific username and duration
func (maker *JWTMaker) CreateToken(username string, duration time.Duration) (string, *Payload, error) {
	// Create payload
	payload, err := NewPayload(username, duration)
	if err != nil {
		return "", nil, err
	}

	// Create JWT claims
	claims := jwt.MapClaims{
		"id":         payload.ID,
		"username":   payload.Username,
		"issued_at":  payload.IssuedAt.Unix(),
		"expired_at": payload.ExpiredAt.Unix(),
	}

	// Create token with claims and sign it
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(maker.secretKey))
	if err != nil {
		return "", nil, err
	}

	return signedToken, payload, nil
}

// VerifyToken checks if the token is valid or not
func (maker *JWTMaker) VerifyToken(tokenString string) (*Payload, error) {
	// Parse the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("invalid signature method: %v", token.Header["alg"])
		}
		return []byte(maker.secretKey), nil
	})

	if err != nil {
		// Check if it's an expired token error
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, err
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	// Convert claims to Payload
	idStr, ok := claims["id"].(string)
	if !ok {
		return nil, errors.New("invalid token id")
	}

	id, err := uuid.Parse(idStr)
	if err != nil {
		return nil, err
	}

	username, ok := claims["username"].(string)
	if !ok {
		return nil, errors.New("invalid username")
	}

	issuedAtUnix, ok := claims["issued_at"].(float64)
	if !ok {
		return nil, errors.New("invalid issued at time")
	}

	expiredAtUnix, ok := claims["expired_at"].(float64)
	if !ok {
		return nil, errors.New("invalid expired at time")
	}

	payload := &Payload{
		ID:        id,
		Username:  username,
		IssuedAt:  time.Unix(int64(issuedAtUnix), 0),
		ExpiredAt: time.Unix(int64(expiredAtUnix), 0),
	}

	return payload, nil
}