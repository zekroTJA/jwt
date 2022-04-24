// jwt is a very simplified implementation of JWTs
// using hashing functions like HS256 or SH512 with
// taking advantage of generic type parameters for
// parsing claims.
package jwt

// Header contains the type of the token, the algorithm
// used to sign and verify the contents of the token as
// well as an optional content type.
//
// Reference:
// https://www.rfc-editor.org/rfc/rfc7519.html#section-5
type Header struct {
	Typ string `json:"typ"`           // Token Type
	Alg string `json:"alg"`           // Verification Algorithm
	Cty string `json:"cty,omitempty"` // Content Type of the claims
}
