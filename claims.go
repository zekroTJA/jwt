package jwt

import "time"

// IValidateExp describes an implementation to check the
// claims 'exp' value against the given current time.
type IValidateExp interface {
	ValidateExp(now time.Time) bool
}

// IValidateNbf describes an implementation to check the
// claims 'nbf' value against the given current time.
type IValidateNbf interface {
	ValidateNbf(now time.Time) bool
}

// PublicClaims contains general public clains as
// specified in RFC7519, Section 4.1.
//
// This struct also implements IValidateExp and
// IValidateNbf to validate the timings of the
// claims.
//
// You can simply extend these claims by your custom
// ones by setting the PublicClaims as an anonymous
// field in your claims model.
// Example:
//   type MyClains struct {
//     PublicClaims
//
//     UserID string `json:"uid"`
//   }
//
//   claims := new(MyClains)
//   claims.UserID = "123"
//   claims.SetExpDuration(15 * time.Minute)
//
// Reference:
// https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1
type PublicClaims struct {
	Iss string `json:"iss,omitempty"` // Issuer
	Sub string `json:"sub,omitempty"` // Subject
	Aud string `json:"aud,omitempty"` // Audience
	Exp int64  `json:"exp,omitempty"` // UNIX Expiration Time
	Nbf int64  `json:"nbf,omitempty"` // UNIX Not Before Time
	Iat int64  `json:"iat,omitempty"` // UNIX Issued At Time
	Jti string `json:"jti,omitempty"` // JWT ID
}

func (t PublicClaims) ValidateExp(now time.Time) bool {
	if t.Exp == 0 {
		return true
	}

	return now.Before(time.Unix(t.Exp, 0))
}

func (t PublicClaims) ValidateNbf(now time.Time) bool {
	if t.Nbf == 0 {
		return true
	}

	return now.After(time.Unix(t.Nbf, 0))
}

// SetExpTime sets 'exp' to the given time.
func (t *PublicClaims) SetExpTime(tm time.Time) {
	t.Exp = tm.Unix()
}

// SetExpDuration sets 'exp' to the time in the given duration.
func (t *PublicClaims) SetExpDuration(duration time.Duration) {
	t.SetExpTime(time.Now().Add(duration))
}

// SetNbfTime sets 'nbf' to the given time.
func (t *PublicClaims) SetNbfTime(tm time.Time) {
	t.Nbf = tm.Unix()
}

// SetNbfDuration sets 'nbf' to the time in the given duration.
func (t *PublicClaims) SetNbfDuration(duration time.Duration) {
	t.SetNbfTime(time.Now().Add(duration))
}

// SetIat sets 'iat' to the current time.
//
// You can also pass a custom time to be set.
func (t *PublicClaims) SetIat(tm ...time.Time) {
	var st time.Time
	if len(tm) != 0 {
		st = tm[0]
	} else {
		st = time.Now()
	}
	t.Iat = st.Unix()
}
