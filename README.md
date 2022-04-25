# jwt

This is a very simplistic implementation of JWT using hashing algorithms like `HS256` or `HS512` and taking advantage of Go 1.18 generic type parameters for parsing claim objects.

This package is very much inspired and influenced by [robbert229's JWT implementation](https://github.com/robbert229/jwt). [Here](https://github.com/robbert229/jwt/blob/master/LICENSE) you can find the projects License.

## Usage

```go
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
```

Go to [example](example) to see the full example.
