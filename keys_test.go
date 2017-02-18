package fireauth_test

import (
	"encoding/json"
	"fmt"
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
		keys   = map[string]string{
			"5e53704fad32e27efe5f32d3b1e0989a0adafcab6": "-----BEGIN CERTIFICATE-----\nMIIDHDCCAgSgAwIBAgIIcUZdMS4lpmswDQYJKoZIhvcNAQEFBQAwMTEvMC0GA1UE\nAxMmc2VjdXJldG9rZW4uc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20wHhcNMTcw\nMjE3MDA0NTI2WhcNMTcwMjIwMDExNTI2WjAxMS8wLQYDVQQDEyZzZWN1cmV0b2tl\nbi5zeXN0ZW0uZ3NlcnZpY2VhY2NvdW50LmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD\nggEPADCCAQoCggEBAK5smXSUrfyfCznhEXZH4MTPghFl0nYfFEgeKeG9OhuQPw0L\nJH6V474PT0ukyzA2x0iXC2wLsDR8A/Xdclbn/OczwoS3DlNF9pDzJ2Sa1lPR4f1Z\nljpo2hWklY9/VrR9wHCVNHFp+fo7g/h3a+DY7ZkP0Eu9IVAjFh4OBsQTsBlYu1FY\nqN5h9Dy+Q1Lf5+tX1JO/c0odsPUli8RFDPSHCxI42AcelogUyWcyhUA3YpT+lvQD\nvfu5FTeNPMkGUurAqeJiDpBPFTBw7yUgKRs5C4gnpfx6rHPxpl3f5Rs9rJWLc87V\n6s2ZMiYJlLVc3+/4V55OxkUoGy6sAHLzULBgJ1MCAwEAAaM4MDYwDAYDVR0TAQH/\nBAIwADAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwIwDQYJ\nKoZIhvcNAQEFBQADggEBACkv67F56wKByJWgw4c4okXf6W6n8YxBkmUJUWN9kQUA\nrVdwkPOcxM24UPJdGr58gTkTUe3sW+K0bGqKRWXttfD620ZRKFO05pIB0fhhX7ei\n4emRwXUkdqvFSZzDlezf25l7wPqu/kmRcWgkJOoc2YGDQs4CPSssOkmkgf51oPzF\nxiMVQ1Wdku005BHdKFe4AZsZ91q5Fyr8z74GyQm8C/uuyP7O4LRcFYEO3FOlzbrt\nynMBsT0Y0NmPN+fKaYfSXzNonPBQax1QVlSWHG8HcmlRqMuVemdSEigwXlw55o5G\nK5Q7wetVYQ9bF6PXhQwa2yRhTpJEOyNIR0vJjQqGSVM=\n-----END CERTIFICATE-----\n",
			"3d7f476544bf10f0024de011f19b6973c210c7ff":  "-----BEGIN CERTIFICATE-----\nMIIDHDCCAgSgAwIBAgIIM/Efol3O2/QwDQYJKoZIhvcNAQEFBQAwMTEvMC0GA1UE\nAxMmc2VjdXJldG9rZW4uc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20wHhcNMTcw\nMjE4MDA0NTI2WhcNMTcwMjIxMDExNTI2WjAxMS8wLQYDVQQDEyZzZWN1cmV0b2tl\nbi5zeXN0ZW0uZ3NlcnZpY2VhY2NvdW50LmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD\nggEPADCCAQoCggEBALLzO5HnxvVyUhOaaji+8l8CmyPCHBMWaljoBZ7JRmJdoCB9\nIkMp1jwDw5JpC756tVVY+Q3NhyBHlmKgqFgUBYdAZAzfCePa0izhrZGndkNRSJug\nFqCQr1skQx741PWU9gu57EF7ZhyoN32LuX5sWuipqi3h+kc+IsnbMcXrFudzFNL3\npMKy0OI5RjLj8MLI0swDpIcgePYz1tpAKFnoXdz4OjvFxvUIv3rXIp8s+OebCDJi\ny122TgJ/dKSiKzRJNUtUt1/ktnYLaj34DcQrBwDQZRAzegxln9RiyMvm8V7MtiRY\ngnO2HwFsVXM5/8yk3EbM3GCG4+6gfdIJjApSTVcCAwEAAaM4MDYwDAYDVR0TAQH/\nBAIwADAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwIwDQYJ\nKoZIhvcNAQEFBQADggEBAHf9PrvYuqsM1kADtzA44p7PZS+l4lK5pIjRRw1dXd6f\nbkrOKGQ26AMJkmtbMuwet0svTKcKM8HpGib7ZMe2kXxkaDODta4eaXxPQOgjedxo\n9MwdlD5qobs135Z0VsXXnTOK3I1jDlST9FBAWi9+oFFuvJ01gLvgNpMcnCGVwkH+\nTgYcaubMkChLR2MX/E4kmdNVY5Ls4WZdet9gjG0aIzfnG9nwS7zzx+ylQSC1RCyU\nj9Br1bT1yecKJeB+T5piWKpVUj9MN8CnN2fA40YWABiL/uRr4p2ghbGp1Pt1sF41\n8cs3QBs9YgdMNWG+S3DNf92nCdF3vATvGPOjiraWYPU=\n-----END CERTIFICATE-----\n", "89e3e1e3feff84bb2c0c5ada3833e7d4b48afd4d": "-----BEGIN CERTIFICATE-----\nMIIDHDCCAgSgAwIBAgIIX08U9EOtLyMwDQYJKoZIhvcNAQEFBQAwMTEvMC0GA1UE\nAxMmc2VjdXJldG9rZW4uc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20wHhcNMTcw\nMjE2MDA0NTI2WhcNMTcwMjE5MDExNTI2WjAxMS8wLQYDVQQDEyZzZWN1cmV0b2tl\nbi5zeXN0ZW0uZ3NlcnZpY2VhY2NvdW50LmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD\nggEPADCCAQoCggEBAN5VpNZAsJcfcwRPyF8nuwXHis90WU/iWwR1hwBm3zpaw2pZ\nlfZrFjGJbIUFcWh+O1f4cIR1NbfEu0oJ5991fuRu1XKnegNPFUrZzEZmkrVXb8br\nJr1upOKkCTB0ErVXZZMNxHcN/3HFil0Ew/TH458+KqOwslyfhpCLJbgVIbhQsEHT\nfqEKNYLi9ptCSTXxA276gYtAwUR4AnJZocl38s5L6NWbVArnhdLSu9fCqp4PNF1K\nSNuLY58YjnnOo9ScV+0s6D1SYNhcHQG9qU8bw9DJg/t+YsxSNUa7PoieP1PxU/Ow\nZaUAHR+GvsSlcIQ8/8OoGlRlH56roUbD6hUyuQUCAwEAAaM4MDYwDAYDVR0TAQH/\nBAIwADAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwIwDQYJ\nKoZIhvcNAQEFBQADggEBAHNsiGSq0BO8CiwXTokIKe9vqXSi7zXQrg5uV3sYjhsx\naFO3pgxh+YiESfgpPhyJuc0Jh90UdthNNOM8IzX/VN9F70wy9WipNYoMQfT9rlrx\nkYGSru/B0IGGpWChcBAzOBYW3aAMELEC9auQBZSayy0tvc0dYCCet0ci2/WuvlyT\n5XAnSVEzrh9PIJEHX4DvapDLIuhwFmCRbs5L7/zaAesm0atOcBxc9ziP2HB76MuU\n+zvUl7TooO8bJXp9c4FQosWKQPbsE3A4gt7DCkTueniHOcn4bxvT6/C11CBXatfk\nkvASvXKAp4mFrrGvcS9P96Tm0+kJ4DSMd3dfhRdIECI=\n-----END CERTIFICATE-----\n",
		}
	)

	BeforeEach(func() {

		var jsonKeys []byte

		jsonKeys, err = json.Marshal(keys)
		Expect(err).ToNot(HaveOccurred())

		// log.Printf("%s", jsonKeys)

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set(HeaderCacheControl, "..., max-age=19008, ...")
			fmt.Fprintln(w, jsonKeys)
		}))
		defer ts.Close()

		serverTokens := make(map[string]interface{})
		maxAge, err = GetKeys(serverTokens, ts.URL)

	})

	// It("should not throw an error", func() {
	// 	Expect(err).NotTo(HaveOccurred())
	// })

	It("should extract maxAge from response header", func() {
		Expect(maxAge).To(Equal(int64(19008)))
	})

})
