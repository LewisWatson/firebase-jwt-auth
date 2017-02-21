package fireauth

import "errors"

var (
	// ErrNilToken is returned when the authorization token is empty
	ErrNilToken = errors.New("Empty authorizatin token")

	// ErrRSAVerification is missing from crypto/ecdsa compared to crypto/rsa
	ErrRSAVerification = errors.New("crypto/rsa: verification error")

	// ErrNotIssuedYet indicates that the token hasn't been issued yet
	ErrNotIssuedYet = errors.New("Token not issued yet")

	// ErrCacheControlHeaderLacksMaxAge indicates that the key server response didnt contain a max age
	// as specified by the firebase docs
	ErrCacheControlHeaderLacksMaxAge = errors.New("cache control header doesn't contain a max age")
)
