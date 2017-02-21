package fireauth

import (
	"io/ioutil"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

var (
	jsonKeys  string
	jsonKeys2 string
)

func TestAuth(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "fireauth test suite")
}

var _ = BeforeSuite(func() {
	content, err := ioutil.ReadFile("testdata/keys.json")
	Expect(err).NotTo(HaveOccurred())
	jsonKeys = string(content)

	content, err = ioutil.ReadFile("testdata/keys2.json")
	Expect(err).NotTo(HaveOccurred())
	jsonKeys2 = string(content)
})
