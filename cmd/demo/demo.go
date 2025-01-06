package main

import (
	"fmt"

	verify "github.com/chaitin/scaptcha-sdk-golang"
)

func main() {
	publicKeyStr := `-----BEGIN PUBLIC KEY-----
	***
-----END PUBLIC KEY-----
		`
	verifyJWTokenken := "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MzU4MTQ5MzMsImlhdCI6MTczNTgxNDYzMywiaXNzIjoiY2hhaXRpbi9zLWNhcHRjaGEiLCJ2aWQiOiI3N2M4M2E2MjNmZDQxMmJlYjczMDYxZDA3MjgzOWIzYyJ9.lna1PIMJ1zM6vwytnEn_6TEjkMb7-ycVRjYRnbDqqVNcjc35OYZ-dpNDPaMOtL7UJPhu7FHNbOV7BjnrGv-XAU_qHQcdTF7jCjV2J8rOQWSyF8htQ5d1Cvm0R2k1A_zsEYmCfAP8S7Dd_kFyShxUfSPmtIbSk8le1VOa3hfxgsBV8QtwxIZDD5l2TjCprYTbLv6vTu7PFZS5cMV68EZ1PvyuJzu9VEUEkhnSjh859mZLOUOQfO5d6M1oAFoBvRKLTLLvd5GGGmUkto40IKW7Gjh5jFEpaKNUX9GBpUMrqWz5fpwNK08oMQEqOdIdr2nfpsSxuZIiK-2QC9X6rlZwPw"
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
