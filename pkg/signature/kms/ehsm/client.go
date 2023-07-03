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
	"strconv"
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
	transitSecretEnginePath string
	keyCache                *ttlcache.Cache[string, crypto.PublicKey]
	keyVersion              uint64
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
	fmt.Println("whh ValidReference")
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
		transitSecretEnginePath: transitSecretEnginePath,
		keyCache: ttlcache.New[string, crypto.PublicKey](
			ttlcache.WithDisableTouchOnHit[string, crypto.PublicKey](),
		),
		keyVersion: keyVersion,
	}

	return ehsmClient, nil
}


func (h *ehsmClient) fetchPublicKey() (crypto.PublicKey, error) {
	fmt.Println("whh fetchPublicKey")
	KeyIDFileName := fmt.Sprintf("./keyname/%s", h.keyPath)
	keyid, _ := ioutil.ReadFile(KeyIDFileName)
	// client := h.clients.Logical()

	// path := fmt.Sprintf("/keys/%s", h.keyPath)

	// _, err := client.Read(path)
	// if err != nil {
	// 	return nil, fmt.Errorf("public key: %w", err)
	// }

	return h.client.Getpubkey(string(keyid))
}


func (h *ehsmClient) sign(digest []byte, alg crypto.Hash, opts ...signature.SignOption) ([]byte, error) {
	client := h.clients.Logical()

	keyVersion := fmt.Sprintf("%d", h.keyVersion)
	var keyVersionUsedPtr *string
	for _, opt := range opts {
		opt.ApplyKeyVersion(&keyVersion)
		opt.ApplyKeyVersionUsed(&keyVersionUsedPtr)
	}

	if keyVersion != "" {
		if _, err := strconv.ParseUint(keyVersion, 10, 64); err != nil {
			return nil, fmt.Errorf("parsing requested key version: %w", err)
		}
	}
	
	signResult, err := client.Write(fmt.Sprintf("/%s/sign/%s%s", h.transitSecretEnginePath, h.keyPath, hashString(alg)), map[string]interface{}{
		"input":       base64.StdEncoding.Strict().EncodeToString(digest),
		"prehashed":   alg != crypto.Hash(0),
		"key_version": keyVersion,
	})
	if err != nil {
		return nil, fmt.Errorf("transit: failed to sign payload: %w", err)
	}

	encodedSignature, ok := signResult.Data["signature"]
	if !ok {
		return nil, errors.New("transit: response corrupted in-transit")
	}

	return vaultDecode(encodedSignature)
}

func (h ehsmClient) verify(sig, digest []byte, alg crypto.Hash, opts ...signature.VerifyOption) error {
	fmt.Println("whh verify")
	client := h.clients.Logical()
	encodedSig := base64.StdEncoding.EncodeToString(sig)

	keyVersion := ""
	for _, opt := range opts {
		opt.ApplyKeyVersion(&keyVersion)
	}

	var vaultDataPrefix string
	if keyVersion != "" {
		// keyVersion >= 1 on verification but can be set to 0 on signing
		kvUint, err := strconv.ParseUint(keyVersion, 10, 64)
		if err != nil {
			return fmt.Errorf("parsing requested key version: %w", err)
		} else if kvUint == 0 {
			return errors.New("key version must be >= 1")
		}

		vaultDataPrefix = fmt.Sprintf("vault:v%d:", kvUint)
	} else {
		vaultDataPrefix = os.Getenv("VAULT_KEY_PREFIX")
		if vaultDataPrefix == "" {
			if h.keyVersion > 0 {
				vaultDataPrefix = fmt.Sprintf("ehsm:v%d:", h.keyVersion)
			} else {
				vaultDataPrefix = vaultV1DataPrefix
			}
		}
	}

	result, err := client.Write(fmt.Sprintf("/%s/verify/%s/%s", h.transitSecretEnginePath, h.keyPath, hashString(alg)), map[string]interface{}{
		"input":     base64.StdEncoding.EncodeToString(digest),
		"prehashed": alg != crypto.Hash(0),
		"signature": fmt.Sprintf("%s%s", vaultDataPrefix, encodedSig),
	})
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}

	valid, ok := result.Data["valid"]
	if !ok {
		return errors.New("corrupted response")
	}

	isValid, ok := valid.(bool)
	if !ok {
		return fmt.Errorf("received non-bool value from 'valid' key")
	}

	if !isValid {
		return errors.New("failed vault verification")
	}

	return nil
}

// Vault likes to prefix base64 data with a version prefix
func vaultDecode(data interface{}) ([]byte, error) {
	fmt.Println("whh vaultDecode")
	encoded, ok := data.(string)
	if !ok {
		return nil, errors.New("received non-string data")
	}

	return base64.StdEncoding.DecodeString(prefixRegex.ReplaceAllString(encoded, ""))
}

func hashString(h crypto.Hash) string {
	fmt.Println("whh hashString")
	var hashStr string
	switch h {
	case crypto.SHA224:
		hashStr = "/sha2-224"
	case crypto.SHA256:
		hashStr = "/sha2-256"
	case crypto.SHA384:
		hashStr = "/sha2-384"
	case crypto.SHA512:
		hashStr = "/sha2-512"
	default:
		hashStr = ""
	}
	return hashStr
}

func (a ehsmClient) createKey(typeStr string) (crypto.PublicKey, error) {
	fmt.Println("lstcreateKey")

	key := a.client.CreateKey(typeStr, "EH_INTERNAL_KEY", "", "", "")

	keybyte := []byte(key)
	// a.keyid = key
	KeyIDFileName := fmt.Sprintf("/keyname/%s", a.keyPath)
	file, err := os.OpenFile(KeyIDFileName, os.O_RDONLY, 755)
	defer file.Close()
	file.Write(keybyte)
	if err != nil {
		panic(err)
	}
	
	fmt.Fprintln(os.Stderr, "KeyId written to", KeyIDFileName)
	return a.fetchPublicKey()
}