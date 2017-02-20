package fireauth_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"

	. "github.com/LewisWatson/firebase-jwt-auth"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Keys", func() {

	var (
		maxAge       int64
		err          error
		serverTokens map[string]interface{}
	)

	BeforeEach(func() {

		if serverTokens == nil {

			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set(HeaderCacheControl, "..., max-age=19008, ...")
				fmt.Fprintln(w, jsonKeys)
			}))
			defer ts.Close()

			serverTokens = make(map[string]interface{})
			maxAge, err = GetKeys(serverTokens, ts.URL)
		}
	})

	It("should not throw an error", func() {
		Expect(err).NotTo(HaveOccurred())
	})

	It("should extract maxAge from response header", func() {
		Expect(maxAge).To(Equal(int64(19008)))
	})

	It("should populate serverTokens with four keys", func() {
		Expect(len(serverTokens)).To(Equal(4))
	})

})
