package fireauth_test

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"

	. "github.com/LewisWatson/firebase-jwt-auth"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Keys", func() {

	var (
		maxAge int64
		err    error
	)

	BeforeEach(func() {

		content, err := ioutil.ReadFile("testkeys.json")
		Expect(err).NotTo(HaveOccurred())

		var jsonKeys []byte
		jsonKeys, err = json.Marshal(content)
		Expect(err).ToNot(HaveOccurred())

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set(HeaderCacheControl, "..., max-age=19008, ...")
			fmt.Fprintln(w, jsonKeys)
		}))
		defer ts.Close()

		serverTokens := make(map[string]interface{})
		maxAge, err = GetKeys(serverTokens, ts.URL)

	})

	It("should not throw an error", func() {
		Expect(err).NotTo(HaveOccurred())
	})

	It("should extract maxAge from response header", func() {
		Expect(maxAge).To(Equal(int64(19008)))
	})

})
