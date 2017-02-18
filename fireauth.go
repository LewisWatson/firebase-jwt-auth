// Package fireauth provides ability to verify firebase authentication ID tokens
package fireauth

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/jose.v1/crypto"
	"gopkg.in/jose.v1/jws"
	"gopkg.in/jose.v1/jwt"
)

// FireAuth module to verify and extract information from Firebase JWT tokens
type FireAuth struct {
	projectID          string
	publicKeys         map[string]*rsa.PublicKey
	cacheControlMaxAge int64
	keysLastUpdatesd   int64
	sync.RWMutex
}

// New creates a new instance of FireAuth and loads the latest keys from the Firebase servers
func New(projectID string) (*FireAuth, error) {
	fb := new(FireAuth)
	fb.projectID = projectID
	return fb, fb.UpdatePublicKeys()
}

// UpdatePublicKeys retrieves the latest Firebase keys
func (fb *FireAuth) UpdatePublicKeys() error {
	log.Printf("Requesting Firebase tokens")
	tokens := make(map[string]interface{})
	maxAge, err := getFirebaseTokens(tokens)
	if err != nil {
		return err
	}
	fb.Lock()
	fb.cacheControlMaxAge = maxAge
	fb.publicKeys = make(map[string]*rsa.PublicKey)
	for kid, token := range tokens {
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

var myClient = &http.Client{Timeout: 30 * time.Second}

// FireAuth tokens must be signed by one of the keys provided via a url.
// The keys expire after a certain amount of time so we need to track that also.
func getFirebaseTokens(tokens map[string]interface{}) (int64, error) {
	r, err := myClient.Get("https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com")
	if err != nil {
		return 0, err
	}
	maxAge, err := extractMaxAge(r.Header.Get("Cache-Control"))
	if err != nil {
		return maxAge, err
	}
	defer r.Body.Close()
	return maxAge, json.NewDecoder(r.Body).Decode(&tokens)
}

// Extract the max age from the cache control response header value
// The cache control header should look similar to "..., max-age=19008, ..."
func extractMaxAge(cacheControl string) (int64, error) {
	// "..., max-age=19008, ..."" to ["..., max-age="]["19008, ..."]
	tokens := strings.Split(cacheControl, "max-age=")
	if len(tokens) == 1 {
		return 0, fmt.Errorf("cache control header doesn't contain a max age")
	}
	// "19008, ..." to ["19008"][" ..."]
	tokens2 := strings.Split(tokens[1], ",")
	// convert "19008" to int64
	return strconv.ParseInt(tokens2[0], 10, 64)
}

// checks if the current FireAuth keys are stale and therefore need updating
func (fb *FireAuth) keysStale() bool {
	return (time.Now().UnixNano() - fb.keysLastUpdatesd) > fb.cacheControlMaxAge
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
		log.Println("FireAuth keys stale")
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
		validatior.SetAudience(fb.projectID)
		validatior.SetIssuer("https://securetoken.google.com/" + fb.projectID)
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
