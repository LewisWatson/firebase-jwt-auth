// +build integration

package fireauth

import (
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("fireauth integration test", func() {

	var (
		firebase *FireAuth
		err      error
	)

	BeforeEach(func() {
		firebase, err = New("example project")
	})

	It("should not thow an error", func() {
		Expect(err).NotTo(HaveOccurred())
	})

	It("should have updated keys in the last second", func() {
		timeKeysLastUpdated := time.Unix(firebase.keysLastUpdatesd, 0)
		Expect(timeKeysLastUpdated).Should(BeTemporally("~", firebase.Clock.Now(), time.Second))
	})
})
