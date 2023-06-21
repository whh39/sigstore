package ehsm

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	vault "github.com/hashicorp/vault/api"
	"github.com/jellydator/ttlcache/v3"
	"github.com/mitchellh/go-homedir"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	sigkms "github.com/sigstore/sigstore/pkg/signature/kms"

	"github.com/whh39/ehsm/go"
)

func init() {
	sigkms.AddProvider(ReferenceScheme, func(_ context.Context, keyResourceID string, hashFunc crypto.Hash, opts ...signature.RPCOption) (sigkms.SignerVerifier, error) {
		return LoadSignerVerifier(keyResourceID, hashFunc, opts...)
	})
}

type ehsmClient struct {
	client                  *vault.Client
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

	if address == "" {
		address = os.Getenv("VAULT_ADDR")
	}
	if address == "" {
		return nil, errors.New("VAULT_ADDR is not set")
	}

	client, err := vault.NewClient(&vault.Config{
		Address: address,
	})
	if err != nil {
		return nil, fmt.Errorf("new vault client: %w", err)
	}

	if token == "" {
		token = os.Getenv("VAULT_TOKEN")
	}
	if token == "" {
		log.Printf("VAULT_TOKEN is not set, trying to read token from file at path ~/.vault-token")
		homeDir, err := homedir.Dir()
		if err != nil {
			return nil, fmt.Errorf("get home directory: %w", err)
		}

		tokenFromFile, err := os.ReadFile(filepath.Join(homeDir, ".vault-token"))
		if err != nil {
			return nil, fmt.Errorf("read .vault-token file: %w", err)
		}

		token = string(tokenFromFile)
	}
	client.SetToken(token)

	// if transitSecretEnginePath == "" {
	// 	transitSecretEnginePath = os.Getenv("TRANSIT_SECRET_ENGINE_PATH")
	// }
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

func (h *ehsmClient) fetchPublicKey(_ context.Context) (crypto.PublicKey, error) {
	fmt.Println("whh fetchPublicKey")
	client := h.client.Logical()

	path := fmt.Sprintf("/%s/keys/%s", h.transitSecretEnginePath, h.keyPath)

	keyResult, err := client.Read(path)
	if err != nil {
		return nil, fmt.Errorf("public key: %w", err)
	}

	if keyResult == nil {
		return nil, fmt.Errorf("could not read data from transit key path: %s", path)
	}

	keysData, hasKeys := keyResult.Data["keys"]
	latestVersion, hasVersion := keyResult.Data["latest_version"]
	if !hasKeys || !hasVersion {
		return nil, errors.New("failed to read transit key keys: corrupted response")
	}

	keys, ok := keysData.(map[string]interface{})
	if !ok {
		return nil, errors.New("failed to read transit key keys: Invalid keys map")
	}

	keyVersion, ok := latestVersion.(json.Number)
	if !ok {
		return nil, fmt.Errorf("format of 'latest_version' is not json.Number")
	}

	keyData, ok := keys[string(keyVersion)]
	if !ok {
		return nil, errors.New("failed to read transit key keys: corrupted response")
	}

	keyMap, ok := keyData.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("could not parse transit key keys data as map[string]interface{}")
	}

	publicKeyPem, ok := keyMap["public_key"]
	if !ok {
		return nil, errors.New("failed to read transit key keys: corrupted response")
	}

	strPublicKeyPem, ok := publicKeyPem.(string)
	if !ok {
		return nil, fmt.Errorf("could not parse public key pem as string")
	}

	return cryptoutils.UnmarshalPEMToPublicKey([]byte(strPublicKeyPem))
}

func (h *ehsmClient) public() (crypto.PublicKey, error) {
	fmt.Println("whh public")
	var lerr error
	loader := ttlcache.LoaderFunc[string, crypto.PublicKey](
		func(c *ttlcache.Cache[string, crypto.PublicKey], key string) *ttlcache.Item[string, crypto.PublicKey] {
			var pubkey crypto.PublicKey
			pubkey, lerr = h.fetchPublicKey(context.Background())
			if lerr == nil {
				item := c.Set(key, pubkey, 300*time.Second)
				return item
			}
			return nil
		},
	)

	item := h.keyCache.Get(cacheKey, ttlcache.WithLoader[string, crypto.PublicKey](loader))
	return item.Value(), lerr
}

func (h ehsmClient) sign(digest []byte, alg crypto.Hash, opts ...signature.SignOption) ([]byte, error) {
	fmt.Println("whh sign")
	client := h.client.Logical()

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

	return vaultDecode(encodedSignature, keyVersionUsedPtr)
}

func (h ehsmClient) verify(sig, digest []byte, alg crypto.Hash, opts ...signature.VerifyOption) error {
	fmt.Println("whh verify")
	client := h.client.Logical()
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
				vaultDataPrefix = fmt.Sprintf("vault:v%d:", h.keyVersion)
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
func vaultDecode(data interface{}, keyVersionUsed *string) ([]byte, error) {
	fmt.Println("whh vaultDecode")
	encoded, ok := data.(string)
	if !ok {
		return nil, errors.New("received non-string data")
	}

	if keyVersionUsed != nil {
		*keyVersionUsed = prefixRegex.FindString(encoded)
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

func (a ehsmClient) createKeyS() (crypto.PublicKey, error) {
	return ehsm.Getpubkey()
}