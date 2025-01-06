package verify

import (
	"crypto/rsa"
	"fmt"
	"sync"
	"time"

	"github.com/chaitin/scaptcha-sdk-golang/utils"
	"github.com/golang-jwt/jwt/v5"
)

// 可能需要返回给用户业务的数据，v-id、score等
type VerifyClaims struct {
	VerifyID string `json:"vid"`
}

// TokenVerifier 处理 JWT token 的验证和防重放
type TokenVerifier struct {
	publicKey *rsa.PublicKey
	// 使用 sync.Map 替代普通 map，专门用于并发场景
	usedTokens sync.Map
	// 清理间隔
	cleanupInterval time.Duration
	// 停止清理的信号
	stopCleanup chan struct{}
}

// NewTokenVerifier 创建新的 TokenVerifier
func NewTokenVerifier(publicKeyStr string) (*TokenVerifier, error) {
	publicKey, err := utils.ParsePublicKey(utils.FormatPublicKey(publicKeyStr))
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA public key: %w", err)
	}
	v := &TokenVerifier{
		publicKey:       publicKey,
		cleanupInterval: 5 * time.Second,
		stopCleanup:     make(chan struct{}),
	}
	go v.startCleanupRoutine()
	return v, nil
}

// startCleanupRoutine 启动定期清理过期 token 的 goroutine
func (v *TokenVerifier) startCleanupRoutine() {
	ticker := time.NewTicker(v.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			v.cleanup(time.Now().Unix())
		case <-v.stopCleanup:
			return
		}
	}
}

// cleanup 清理过期的 token
func (v *TokenVerifier) cleanup(now int64) {
	v.usedTokens.Range(func(key, value interface{}) bool {
		if expTime, ok := value.(int64); ok && expTime < now {
			v.usedTokens.Delete(key)
		}
		return true
	})
}

// Stop 停止清理 routine
func (v *TokenVerifier) Stop() {
	close(v.stopCleanup)
}

// VerifyToken 验证 token 并防止重放攻击
func (v *TokenVerifier) VerifyToken(tokenString string) (bool, VerifyClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return v.publicKey, nil
	})
	if err != nil {
		return false, VerifyClaims{}, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return false, VerifyClaims{}, fmt.Errorf("failed to get claims")
	}

	// 验证过期时间
	exp, err := claims.GetExpirationTime()
	if err != nil {
		return false, VerifyClaims{}, fmt.Errorf("exp not found")
	}
	if exp.Unix() < time.Now().Unix() {
		return false, VerifyClaims{}, fmt.Errorf("token expired")
	}

	// 验证并记录 verify id 防止重放
	verifyID, ok := claims["vid"].(string)
	if !ok {
		return false, VerifyClaims{}, fmt.Errorf("invalid verify id")
	}

	// 使用 LoadOrStore 原子性地检查和存储
	if _, loaded := v.usedTokens.LoadOrStore(verifyID, exp.Unix()); loaded {
		return false, VerifyClaims{}, fmt.Errorf("token already used")
	}
	verifyClaims := VerifyClaims{
		VerifyID: verifyID,
	}
	return true, verifyClaims, nil
}
