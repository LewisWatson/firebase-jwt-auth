// Package fireauth provides ability to verify firebase authentication ID tokens
package fireauth

import (
	"crypto/rsa"
	"strings"
	"sync"

	"github.com/benbjohnson/clock"

	"gopkg.in/jose.v1/crypto"
	"gopkg.in/jose.v1/jws"
	"gopkg.in/jose.v1/jwt"
)

type claimTimeOverride struct {
	exp int64
	iat int64
}

// FireAuth module to verify and extract information from Firebase JWT tokens
type FireAuth struct {
	ProjectID         string
	publicKeys        map[string]*rsa.PublicKey
	keyExpire         int64
	KeyURL            string
	IssPrefix         string
	Clock             clock.Clock
	claimTimeOverride *claimTimeOverride
	sync.RWMutex
}

const (
	// FirebaseKeyURL Firebase key provider url
	// specified in https://firebase.google.com/docs/auth/admin/verify-id-tokens#verify_id_tokens_using_a_third-party_jwt_library
	FirebaseKeyURL = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"

	// IssPrefix JWT issuer prefix
	// specified in https://firebase.google.com/docs/auth/admin/verify-id-tokens#verify_id_tokens_using_a_third-party_jwt_library
	IssPrefix = "https://securetoken.google.com/"
)

// New creates a new instance of FireAuth with default values and loads the latest keys from the Firebase servers
func New(projectID string) (*FireAuth, error) {
	fb := new(FireAuth)
	fb.ProjectID = projectID
	fb.KeyURL = FirebaseKeyURL
	fb.IssPrefix = IssPrefix
	fb.Clock = clock.New()
	return fb, fb.UpdatePublicKeys()
}

// Verify to satisfy the fireauth.TokenVerifier interface
func (fb *FireAuth) Verify(accessToken string) (string, jwt.Claims, error) {

	// empty string is clearly invalid
	if accessToken == "" {
		return "", nil, ErrNilToken
	}

	token, err := jws.ParseJWT([]byte(accessToken))
	if err != nil {
		return "", nil, err
	}

	if fb.keysStale() {
		fb.UpdatePublicKeys()
	}

	// test override
	if fb.claimTimeOverride != nil {
		token.Claims().Set("exp", fb.claimTimeOverride.exp)
		token.Claims().Set("iat", fb.claimTimeOverride.iat)
	}

	fb.RLock()

	// BUG(lewis) should extract kid from header and only verify against that key

	// validate against FireAuth keys
	for _, key := range fb.publicKeys {
		err = token.Validate(key, crypto.SigningMethodRS256)
		// verification errors indicate that the token isn't valid for this key
		if err == nil || !strings.Contains(err.Error(), "verification error") {
			break
		}
	}

	fb.RUnlock()

	if err == nil {
		iat, ok := token.Claims().IssuedAt()
		if !ok || fb.Clock.Now().Before(iat) {
			err = ErrNotIssuedYet
		}
	}

	if err == nil {
		validatior := jwt.Validator{}
		validatior.SetAudience(fb.ProjectID)
		validatior.SetIssuer(fb.IssPrefix + fb.ProjectID)
		err = validatior.Validate(token)
	}

	// convert library errors into auth errors

	switch err {
	case jwt.ErrTokenIsExpired:
		err = ErrTokenExpired
		break
	case crypto.ErrECDSAVerification:
		err = ErrECDSAVerification
		break
	case jws.ErrNotCompact:
		err = ErrNotCompact
		break
	case jwt.ErrInvalidISSClaim:
		err = ErrInvalidIss
		break
	case jwt.ErrInvalidAUDClaim:
		err = ErrInvalidAud
		break
	}

	return token.Claims().Get("sub").(string), token.Claims(), err
}

// checks if the current FireAuth keys are stale and therefore need updating
func (fb *FireAuth) keysStale() bool {
	return fb.Clock.Now().Unix() > fb.keyExpire
}

// UpdatePublicKeys retrieves the latest Firebase keys
func (fb *FireAuth) UpdatePublicKeys() error {

	fb.Lock()
	defer fb.Unlock()

	// check if keys are still stale. Maybe another thread has refreshed
	if !fb.keysStale() {
		return nil
	}

	serverTokens := make(map[string]interface{})
	maxAge, err := GetKeys(serverTokens, fb.KeyURL)
	if err != nil {
		return err
	}
	expire := fb.Clock.Now().Unix() + maxAge

	fb.publicKeys = make(map[string]*rsa.PublicKey)
	for kid, token := range serverTokens {
		publicKey, err := crypto.ParseRSAPublicKeyFromPEM([]byte(token.(string)))
		if err != nil {
			return err
		}
		fb.publicKeys[kid] = publicKey
	}

	fb.keyExpire = expire

	return nil
}

func (fb *FireAuth) setClaimTimeOverride(cto *claimTimeOverride) {
	fb.claimTimeOverride = cto
}
