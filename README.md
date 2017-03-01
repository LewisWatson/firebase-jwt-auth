# Firebase Authentication JWT Verifier

[![Build Status](https://travis-ci.org/LewisWatson/firebase-jwt-auth.svg?branch=master)](https://travis-ci.org/LewisWatson/firebase-jwt-auth)
[![Coverage Status](https://coveralls.io/repos/github/LewisWatson/firebase-jwt-auth/badge.svg?branch=master)](https://coveralls.io/github/LewisWatson/firebase-jwt-auth?branch=master)
[![GoDoc](https://godoc.org/github.com/SermoDigital/jose?status.svg)](https://godoc.org/github.com/LewisWatson/firebase-jwt-auth)
[![stability-stable](https://img.shields.io/badge/stability-stable-green.svg)](https://github.com/emersion/stability-badges#stable)
[![Sourcegraph](https://sourcegraph.com/github.com/LewisWatson/firebase-jwt-auth/-/badge.svg)](https://sourcegraph.com/github.com/LewisWatson/firebase-jwt-auth?badge)

This library follows the instructions described in [verify id tokens using third-party JWT library](https://firebase.google.com/docs/auth/admin/verify-id-tokens#verify_id_tokens_using_a_third-party_jwt_library) section of the firebase documentation.

[Firebase]: https://firebase.google.com/ "Firebase"
[JWT]: https://jwt.io/ "JWT"

## Example Usage

```go
import (
	"gopkg.in/LewisWatson/firebase-jwt-auth.v1"
	"github.com/manyminds/api2go"
)

// tokenVerifier previously initialised with fireauth.New("projectname")
func verify(r api2go.Request, tokenVerifier fireauth.TokenVerifier) error {
	token := r.Header.Get("authorization")
	userID, claims, err := tokenVerifier.Verify(token)
	if err != nil {
		return err
	}
	r.Context.Set("userID", userID)
	r.Context.Set("claims", claims)
	return nil
}
