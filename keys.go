package fireauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// HeaderCacheControl Cache-Control field in http response header
const HeaderCacheControl = "Cache-Control"

var myClient = &http.Client{Timeout: 30 * time.Second}

// GetKeys client tokens must be signed by one of the server keys provided via a url.
// The keys expire after a certain amount of time so we need to track that also.
func GetKeys(tokens map[string]interface{}, keyURL string) (int64, error) {
	r, err := myClient.Get(keyURL)
	if err != nil {
		return 0, err
	}
	maxAge, err := extractMaxAge(r.Header.Get(HeaderCacheControl))
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
