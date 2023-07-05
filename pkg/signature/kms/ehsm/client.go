package ehsm

import (
	"context"
	"crypto"
	"encoding/base64"
	// "encoding/json"
	"errors"
	"fmt"
	// "log"
	"os"
	// "path/filepath"
	"regexp"
	// "strconv"
	// "time"
	"io/ioutil"

	vault "github.com/hashicorp/vault/api"
	"github.com/jellydator/ttlcache/v3"
	// "github.com/mitchellh/go-homedir"
	// "github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	sigkms "github.com/sigstore/sigstore/pkg/signature/kms"

	ehsm "github.com/whh39/ehsm/go"
)

func init() {
	sigkms.AddProvider(ReferenceScheme, func(_ context.Context, keyResourceID string, hashFunc crypto.Hash, opts ...signature.RPCOption) (sigkms.SignerVerifier, error) {
		return LoadSignerVerifier(keyResourceID, hashFunc, opts...)
	})
}

type ehsmClient struct {
	client                  *ehsm.Client
	clients					*vault.Client
	keyid 					string
	keyPath                 string
	keyCache                *ttlcache.Cache[string, crypto.PublicKey]
}

var (
	errReference   = errors.New("kms specification should be in the format ehsm://<key>")
	referenceRegex = regexp.MustCompile(`^ehsm://(?P<path>\w(([\w-.]+)?\w)?)$`)
	prefixRegex    = regexp.MustCompile("^ehsm:v[0-9]+:")
)

const (
	vaultV1DataPrefix = "ehsm:v1:"

	// use a consistent key for cache lookups
	cacheKey = "signer"

	// ReferenceScheme schemes for various KMS services are copied from https://github.com/google/go-cloud/tree/master/secrets
	ReferenceScheme = "ehsm://"
)

// ValidReference returns a non-nil error if the reference string is invalid
func ValidReference(ref string) error {
	if !referenceRegex.MatchString(ref) {
		return errReference
	}
	return nil
}

func parseReference(resourceID string) (keyPath string, err error) {
	fmt.Println("whh parseReference")
	i := referenceRegex.SubexpIndex("path")
	v := referenceRegex.FindStringSubmatch(resourceID)
	if len(v) < i+1 {
		err = fmt.Errorf("invalid vault format %q: %w", resourceID, err)
		return
	}
	keyPath = v[i]
	return
}

func newEhsmClient(address, token, transitSecretEnginePath, keyResourceID string, keyVersion uint64) (*ehsmClient, error) {
	fmt.Println("whh newHashivaultClient")
	if err := ValidReference(keyResourceID); err != nil {
		return nil, err
	}

	keyPath, err := parseReference(keyResourceID)
	if err != nil {
		return nil, err
	}

	client := ehsm.NewClient()

	// if token == "" {
	// 	token = os.Getenv("VAULT_TOKEN")
	// }
	// if token == "" {
	// 	log.Printf("VAULT_TOKEN is not set, trying to read token from file at path ~/.vault-token")
	// 	homeDir, err := homedir.Dir()
	// 	if err != nil {
	// 		return nil, fmt.Errorf("get home directory: %w", err)
	// 	}

	// 	tokenFromFile, err := os.ReadFile(filepath.Join(homeDir, ".vault-token"))
	// 	if err != nil {
	// 		return nil, fmt.Errorf("read .vault-token file: %w", err)
	// 	}

	// 	token = string(tokenFromFile)
	// }
	// client.SetToken(token)
	if transitSecretEnginePath == "" {
		transitSecretEnginePath = "transit"
	}

	ehsmClient := &ehsmClient{
		client:                  client,
		keyPath:                 keyPath,
		keyCache: ttlcache.New[string, crypto.PublicKey](
			ttlcache.WithDisableTouchOnHit[string, crypto.PublicKey](),
		),
	}

	return ehsmClient, nil
}


func (h *ehsmClient) fetchPublicKey() (crypto.PublicKey, error) {
	fmt.Println("whh fetchPublicKey")
	KeyIDFileName := fmt.Sprintf("./%s", h.keyPath)
	keyid, _ := ioutil.ReadFile(KeyIDFileName)

	return h.client.Getpubkey(string(keyid))
}


func (h *ehsmClient) sign(digest []byte, alg crypto.Hash, opts ...signature.SignOption) ([]byte, error) {
	fmt.Println("whh sign")
	encodedigest := base64.StdEncoding.Strict().EncodeToString(digest)
	KeyIDFileName := fmt.Sprintf("./%s", h.keyPath)
	keyid, _ := ioutil.ReadFile(KeyIDFileName)

	signature, _ := h.client.Sign(string(keyid), encodedigest)

	encodedSignature,err := base64.StdEncoding.DecodeString(signature)
	return []byte(encodedSignature), err
}

func (h ehsmClient) verify(sig, digest []byte, alg crypto.Hash, opts ...signature.VerifyOption) error {
	fmt.Println("whh verify")
	encodedSig := base64.StdEncoding.EncodeToString(sig)

	// keyVersion := ""
	// for _, opt := range opts {
	// 	opt.ApplyKeyVersion(&keyVersion)
	// }

	// var vaultDataPrefix string
	// if keyVersion != "" {
	// 	// keyVersion >= 1 on verification but can be set to 0 on signing
	// 	kvUint, err := strconv.ParseUint(keyVersion, 10, 64)
	// 	if err != nil {
	// 		return fmt.Errorf("parsing requested key version: %w", err)
	// 	} else if kvUint == 0 {
	// 		return errors.New("key version must be >= 1")
	// 	}

	// 	vaultDataPrefix = fmt.Sprintf("vault:v%d:", kvUint)
	// } else {
	// 	vaultDataPrefix = os.Getenv("VAULT_KEY_PREFIX")
	// 	if vaultDataPrefix == "" {
	// 		if h.keyVersion > 0 {
	// 			vaultDataPrefix = fmt.Sprintf("ehsm:v%d:", h.keyVersion)
	// 		} else {
	// 			vaultDataPrefix = vaultV1DataPrefix
	// 		}
	// 	}
	// }
	encodedigest := base64.StdEncoding.Strict().EncodeToString(digest)
	KeyIDFileName := fmt.Sprintf("./%s", h.keyPath)
	keyid, _ := ioutil.ReadFile(KeyIDFileName)
	result, err := h.client.Verify(string(keyid), encodedigest, encodedSig)
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}

	if !result {
		return errors.New("failed vault verification")
	}

	return nil
}

func (a ehsmClient) createKey(typeStr string) (crypto.PublicKey, error) {
	fmt.Println("lstcreateKey")

	key := a.client.CreateKey(typeStr, "EH_INTERNAL_KEY", "", "EH_PAD_RSA_PKCS1_PSS", "EH_SHA_2_256")

	keybyte := []byte(key)
	// a.keyid = key
	KeyIDFileName := fmt.Sprintf("./%s", a.keyPath)
	file, err := os.OpenFile(KeyIDFileName, os.O_CREATE|os.O_RDWR, 0600)
	defer file.Close()
	file.Write(keybyte)
	if err != nil {
		panic(err)
	}
	
	fmt.Fprintln(os.Stderr, "KeyId written to", a.keyPath)
	return a.fetchPublicKey()
}