package main

import (
	"log"
	"time"

	"github.com/zekrotja/jwt"
)

type Claims struct {
	jwt.PublicClaims

	UserID string `json:"uid"`
}

func main() {
	const signingSecret = "3U5o3Z#XqfLpr3pjGknwWa^u6)CCo&&G"

	algorithm := jwt.NewHmacSha512([]byte(signingSecret))
	handler := jwt.NewHandler[Claims](algorithm)

	claims := new(Claims)
	claims.UserID = "221905671296253953"
	claims.Iss = "jwt example"
	claims.SetIat()
	claims.SetExpDuration(15 * time.Minute)
	claims.SetNbfTime(time.Now())

	token, err := handler.EncodeAndSign(*claims)
	if err != nil {
		log.Fatalf("Token generation failed: %s", err.Error())
	}

	log.Printf("Token generated: %s", token)

	recoveredClaims, err := handler.DecodeAndValidate(token)
	if err != nil {
		log.Fatalf("Token validation failed: %s", err.Error())
	}

	log.Printf("Recovered claims: %+v", recoveredClaims)
}
