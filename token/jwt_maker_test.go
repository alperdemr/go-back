package token

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestJWTMaker(t *testing.T) {
	secretKey := "12345678901234567890123456789012" // 32-character secret key

	maker, err := NewJWTMaker(secretKey)
	require.NoError(t, err)

	username := "testuser"
	duration := time.Minute

	// Test token creation
	token, payload, err := maker.CreateToken(username, duration)
	require.NoError(t, err)
	require.NotEmpty(t, token)
	require.NotNil(t, payload)

	// Verify payload details
	require.NotZero(t, payload.ID)
	require.Equal(t, username, payload.Username)
	require.WithinDuration(t, time.Now(), payload.IssuedAt, time.Second)
	require.WithinDuration(t, time.Now().Add(duration), payload.ExpiredAt, time.Second)
}

func TestVerifyToken(t *testing.T) {
	secretKey := "12345678901234567890123456789012"
	maker, err := NewJWTMaker(secretKey)
	require.NoError(t, err)

	username := "testuser"
	duration := time.Minute

	// Create a token
	token, payload, err := maker.CreateToken(username, duration)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	// Verify the token
	verifiedPayload, err := maker.VerifyToken(token)
	require.NoError(t, err)
	require.NotNil(t, verifiedPayload)

	// Check verified payload details
	require.Equal(t, payload.ID, verifiedPayload.ID)
	require.Equal(t, username, verifiedPayload.Username)
}

func TestExpiredToken(t *testing.T) {
	secretKey := "12345678901234567890123456789012"
	maker, err := NewJWTMaker(secretKey)
	require.NoError(t, err)

	username := "testuser"
	duration := -time.Minute // Negative duration to create an already expired token

	token, _, err := maker.CreateToken(username, duration)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	// Verify token should return an expired token error
	verifiedPayload, err := maker.VerifyToken(token)
	require.Error(t, err)
	require.Nil(t, verifiedPayload)
	require.ErrorIs(t, err, ErrExpiredToken)
}

func TestInvalidTokens(t *testing.T) {
	secretKey := "12345678901234567890123456789012"
	maker, err := NewJWTMaker(secretKey)
	require.NoError(t, err)

	// Test invalid token (tampered signature)
	invalidToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InRlc3R1c2VyIn0.invalidSignature"
	
	verifiedPayload, err := maker.VerifyToken(invalidToken)
	require.Error(t, err)
	require.Nil(t, verifiedPayload)

	// Test empty token
	verifiedPayload, err = maker.VerifyToken("")
	require.Error(t, err)
	require.Nil(t, verifiedPayload)
}

func TestInvalidSecretKey(t *testing.T) {
	// Test secret key too short
	_, err := NewJWTMaker("short")
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid key size")
}

func TestNewPayload(t *testing.T) {
	username := "testuser"
	duration := time.Minute

	payload, err := NewPayload(username, duration)
	require.NoError(t, err)
	require.NotNil(t, payload)

	// Check payload details
	require.NotZero(t, payload.ID)
	require.Equal(t, username, payload.Username)
	require.WithinDuration(t, time.Now(), payload.IssuedAt, time.Second)
	require.WithinDuration(t, time.Now().Add(duration), payload.ExpiredAt, time.Second)

	// Test payload validity
	err = payload.Valid()
	require.NoError(t, err)

	// Test expired payload
	expiredPayload := &Payload{
		ID:        uuid.New(),
		Username:  username,
		IssuedAt:  time.Now().Add(-2 * time.Minute),
		ExpiredAt: time.Now().Add(-time.Minute),
	}
	err = expiredPayload.Valid()
	require.Error(t, err)
	require.ErrorIs(t, err, ErrExpiredToken)
}