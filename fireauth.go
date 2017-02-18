// Package fireauth provides ability to verify firebase authentication ID tokens
package fireauth

import (
	"crypto/rsa"
	"log"
	"strings"
	"sync"
	"time"

	"gopkg.in/jose.v1/crypto"
	"gopkg.in/jose.v1/jws"
	"gopkg.in/jose.v1/jwt"
)

// FireAuth module to verify and extract information from Firebase JWT tokens
type FireAuth struct {
	ProjectID          string
	publicKeys         map[string]*rsa.PublicKey
	cacheControlMaxAge int64
	keysLastUpdatesd   int64
	KeyURL             string
	IssPrefix          string
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
		log.Println("Firebase keys stale")
		fb.UpdatePublicKeys()
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
	return (time.Now().UnixNano() - fb.keysLastUpdatesd) > fb.cacheControlMaxAge
}

// UpdatePublicKeys retrieves the latest Firebase keys
func (fb *FireAuth) UpdatePublicKeys() error {
	log.Printf("Requesting Firebase tokens")
	serverTokens := make(map[string]interface{})
	maxAge, err := GetKeys(serverTokens, fb.KeyURL)
	if err != nil {
		return err
	}
	fb.Lock()
	fb.cacheControlMaxAge = maxAge
	fb.publicKeys = make(map[string]*rsa.PublicKey)
	for kid, token := range serverTokens {
		publicKey, err := crypto.ParseRSAPublicKeyFromPEM([]byte(token.(string)))
		if err != nil {
			log.Printf("Error parsing kid %s, %v", kid, err)
		} else {
			log.Printf("Validated kid %s", kid)
			fb.publicKeys[kid] = publicKey
		}
	}
	fb.Unlock()
	return nil
}
