package main

import (
	"fmt"

	verify "github.com/chaitin/scaptcha-sdk-golang"
)

func main() {
	publicKeyStr := `publicKeyStr`
	verifyJWTokenken := "this-is-a-token"
	// 创建验证器
	verifier, err := verify.NewTokenVerifier(publicKeyStr)
	if err != nil {
		fmt.Printf("Failed to create token verifier: %v", err)
		return
	}
	defer verifier.Stop() // 确保清理 goroutine 正确退出

	// 验证 token
	checkOk, claims, err := verifier.VerifyToken(verifyJWTokenken)
	if err != nil || !checkOk {
		fmt.Printf("Token verification failed: %v", err)
	}
	fmt.Println("JWT verification success")
	fmt.Println(claims)
}
