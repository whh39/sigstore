//
// Copyright 2022 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package azure implement the interface with microsoft azure kms service
package azure

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"github.com/go-jose/go-jose/v3"
	"github.com/jellydator/ttlcache/v3"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
	"github.com/sigstore/sigstore/pkg/signature"
	sigkms "github.com/sigstore/sigstore/pkg/signature/kms"

	hmac "crypto/hmac"
    sha256 "crypto/sha256"
    tls "crypto/tls"
    // "encoding/base64"
    // "encoding/json"
    // "fmt"
    http "net/http"
    ioutil "io/ioutil"
    // "net/url"
    // "strings"
    // "time"
    "strconv"
    "sort"
    "bytes"
    "github.com/iancoleman/orderedmap"
)


func init() {
	sigkms.AddProvider(ReferenceScheme, func(ctx context.Context, keyResourceID string, hashFunc crypto.Hash, opts ...signature.RPCOption) (sigkms.SignerVerifier, error) {
		return LoadSignerVerifier(ctx, keyResourceID, hashFunc)
	})
}

// type kvClient interface {
// 	CreateKey(ctx context.Context, name string, parameters azkeys.CreateKeyParameters, options *azkeys.CreateKeyOptions) (azkeys.CreateKeyResponse, error)
// 	GetKey(ctx context.Context, name, version string, options *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error)
// 	Sign(ctx context.Context, name, version string, parameters azkeys.SignParameters, options *azkeys.SignOptions) (azkeys.SignResponse, error)
// 	Verify(ctx context.Context, name, version string, parameters azkeys.VerifyParameters, options *azkeys.VerifyOptions) (azkeys.VerifyResponse, error)
// }
//ehsm
type kvClient interface {
	// GetVersion()

	// Enroll()

	CreateKey(keyspec string, origin string) 
    // CreateKey("EH_AES_GCM_128", "EH_INTERNAL_KEY")
	GetKey(ctx context.Context, name, version string, options *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error)
	Sign(ctx context.Context, name, version string, parameters azkeys.SignParameters, options *azkeys.SignOptions) (azkeys.SignResponse, error)
	Verify(ctx context.Context, name, version string, parameters azkeys.VerifyParameters, options *azkeys.VerifyOptions) (azkeys.VerifyResponse, error)
}

type azureVaultClient struct {
	clients   ehsmClient
	client    kvClient
	keyCache  *ttlcache.Cache[string, crypto.PublicKey]
	vaultURL  string
	vaultName string
	keyName   string
}

var (
	// errAzureReference = errors.New("kms specification should be in the format azurekms://[VAULT_NAME][VAULT_URL]/[KEY_NAME]")
	errAzureReference = errors.New("kms specification should be in the format ehsm://[VAULT_NAME][VAULT_URL]/[KEY_NAME]")

	// referenceRegex = regexp.MustCompile(`^azurekms://([^/]+)/([^/]+)?$`)
	referenceRegex = regexp.MustCompile(`^ehsmkms://([^/]+)/([^/]+)?$`)
)

const (
	// // ReferenceScheme schemes for various KMS services are copied from https://github.com/google/go-cloud/tree/master/secrets
	// ReferenceScheme = "azurekms://"
	// cacheKey        = "azure_vault_signer"

	//ehsm
	ReferenceScheme = "ehsmkms://"
	cacheKey        = "ehsm_signer"
)

// ValidReference returns a non-nil error if the reference string is invalid
func ValidReference(ref string) error {
	if !referenceRegex.MatchString(ref) {
		return errAzureReference
	}
	return nil
}

func parseReference(resourceID string) (vaultURL, vaultName, keyName string, err error) {
	v := referenceRegex.FindStringSubmatch(resourceID)
	if len(v) != 3 {
		// err = fmt.Errorf("invalid azurekms format %q", resourceID)
		err = fmt.Errorf("invalid ehsmkms format %q", resourceID)
		return
	}

	vaultURL = fmt.Sprintf("https://%s/", v[1])
	vaultName, keyName = strings.Split(v[1], ".")[0], v[2]
	return
}

func newAzureKMS(keyResourceID string) (*azureVaultClient, error) {
	if err := ValidReference(keyResourceID); err != nil {
		return nil, err
	}
	vaultURL, vaultName, keyName, err := parseReference(keyResourceID)
	if err != nil {
		return nil, err
	}

	client, err := getKeysClient(vaultURL)
	if err != nil {
		return nil, fmt.Errorf("new ehsm kms client: %w", err)
	}

	azClient := &azureVaultClient{ 
		client:    client,
		vaultURL:  vaultURL,
		vaultName: vaultName,
		keyName:   keyName,
		keyCache: ttlcache.New[string, crypto.PublicKey](
			ttlcache.WithDisableTouchOnHit[string, crypto.PublicKey](),
		),
	}

	return azClient, nil
}

type authenticationMethod string

const (
	unknownAuthenticationMethod     = "unknown"
	environmentAuthenticationMethod = "environment"
	cliAuthenticationMethod         = "cli"
)

// getAuthMethod returns the an authenticationMethod to use to get an Azure Authorizer.
// If no environment variables are set, unknownAuthMethod will be used.
// If the environment variable 'AZURE_AUTH_METHOD' is set to either environment or cli, use it.
// If the environment variables 'AZURE_TENANT_ID', 'AZURE_CLIENT_ID' and 'AZURE_CLIENT_SECRET' are set, use environment.
func getAuthenticationMethod() authenticationMethod {
	tenantID := os.Getenv("AZURE_TENANT_ID")
	clientID := os.Getenv("AZURE_CLIENT_ID")
	clientSecret := os.Getenv("AZURE_CLIENT_SECRET")
	authMethod := os.Getenv("AZURE_AUTH_METHOD")

	if authMethod != "" {
		switch strings.ToLower(authMethod) {
		case "environment":
			return environmentAuthenticationMethod
		case "cli":
			return cliAuthenticationMethod
		}
	}

	if tenantID != "" && clientID != "" && clientSecret != "" {
		return environmentAuthenticationMethod
	}

	return unknownAuthenticationMethod
}

type azureCredential interface {
	GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error)
}

// getAzureCredential takes an authenticationMethod and returns an Azure credential or an error.
// If the method is unknown, Environment will be tested and if it returns an error CLI will be tested.
// If the method is specified, the specified method will be used and no other will be tested.
// This means the following default order of methods will be used if nothing else is defined:
// 1. Client credentials (FromEnvironment)
// 2. Client certificate (FromEnvironment)
// 3. Username password (FromEnvironment)
// 4. MSI (FromEnvironment)
// 5. CLI (FromCLI)
func getAzureCredential(method authenticationMethod) (azureCredential, error) {
	switch method {
	case environmentAuthenticationMethod:
		cred, err := azidentity.NewEnvironmentCredential(nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create default azure credential from env auth method: %w", err)
		}
		return cred, nil
	case cliAuthenticationMethod:
		cred, err := azidentity.NewAzureCLICredential(nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create default Azure credential from env auth method: %w", err)
		}
		return cred, nil
	case unknownAuthenticationMethod:
		break
	default:
		return nil, fmt.Errorf("you should never reach this")
	}

	cred, err := azidentity.NewEnvironmentCredential(nil)
	if err == nil {
		return cred, nil
	}

	cred2, err := azidentity.NewAzureCLICredential(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create default Azure credential from env auth method: %w", err)
	}
	return cred2, nil
}

func getKeysClient(vaultURL string) (*azkeys.Client, error) {
	authMethod := getAuthenticationMethod()
	cred, err := getAzureCredential(authMethod)
	if err != nil {
		return nil, err
	}

	client, err := azkeys.NewClient(vaultURL, cred, nil)
	if err != nil {
		return nil, err
	}

	return client, nil
}

func (a *azureVaultClient) fetchPublicKey(ctx context.Context) (crypto.PublicKey, error) {
	keyBundle, err := a.getKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("public key: %w", err)
	}

	key := keyBundle.Key
	keyType := key.Kty

	// Azure Key Vault allows keys to be stored in either default Key Vault storage
	// or in managed HSMs. If the key is stored in a HSM, the key type is suffixed
	// with "-HSM". Since this suffix is specific to Azure Key Vault, it needs
	// be stripped from the key type before attempting to represent the key
	// with a go-jose/JSONWebKey struct.
	switch *keyType {
	case azkeys.JSONWebKeyTypeECHSM:
		*key.Kty = azkeys.JSONWebKeyTypeEC
	case azkeys.JSONWebKeyTypeRSAHSM:
		*key.Kty = azkeys.JSONWebKeyTypeRSA
	}

	jwkJSON, err := json.Marshal(*key)
	if err != nil {
		return nil, fmt.Errorf("encoding the jsonWebKey: %w", err)
	}

	jwk := jose.JSONWebKey{}
	err = jwk.UnmarshalJSON(jwkJSON)
	if err != nil {
		return nil, fmt.Errorf("decoding the jsonWebKey: %w", err)
	}

	return jwk.Key, nil
}

func (a *azureVaultClient) getKey(ctx context.Context) (azkeys.KeyBundle, error) {
	resp, err := a.client.GetKey(ctx, a.vaultURL, a.keyName, nil)
	if err != nil {
		return azkeys.KeyBundle{}, fmt.Errorf("public key: %w", err)
	}

	return resp.KeyBundle, err
}

func (a *azureVaultClient) public(ctx context.Context) (crypto.PublicKey, error) {
	var lerr error
	loader := ttlcache.LoaderFunc[string, crypto.PublicKey](
		func(c *ttlcache.Cache[string, crypto.PublicKey], key string) *ttlcache.Item[string, crypto.PublicKey] {
			ttl := 300 * time.Second
			var pubKey crypto.PublicKey
			pubKey, lerr = a.fetchPublicKey(ctx)
			if lerr == nil {
				return c.Set(cacheKey, pubKey, ttl)
			}
			return nil
		},
	)
	item := a.keyCache.Get(cacheKey, ttlcache.WithLoader[string, crypto.PublicKey](loader))
	if lerr != nil {
		return nil, lerr
	}
	return item.Value(), nil
}

func (a *azureVaultClient) createKey(ctx context.Context) (crypto.PublicKey, error) {
	_, err := a.getKey(ctx)
	if err == nil {
		return a.public(ctx)
	}

	_, err = a.client.CreateKey(
		ctx,
		a.keyName,
		azkeys.CreateKeyParameters{
			KeyAttributes: &azkeys.KeyAttributes{
				Enabled: to.Ptr(true),
			},
			KeySize: to.Ptr(int32(2048)),
			KeyOps: []*azkeys.JSONWebKeyOperation{
				to.Ptr(azkeys.JSONWebKeyOperationSign),
				to.Ptr(azkeys.JSONWebKeyOperationVerify),
			},
			Kty: to.Ptr(azkeys.JSONWebKeyTypeEC),
			Tags: map[string]*string{
				"use": to.Ptr("sigstore"),
			},
		}, nil)
		if err != nil {
			return nil, err
		}

	return a.public(ctx)
}

func (a *azureVaultClient) getKeyVaultHashFunc(ctx context.Context) (crypto.Hash, azkeys.JSONWebKeySignatureAlgorithm, error) {
	publicKey, err := a.public(ctx)
	if err != nil {
		return 0, "", fmt.Errorf("failed to get public key: %w", err)
	}
	switch keyImpl := publicKey.(type) {
	case *ecdsa.PublicKey:
		switch keyImpl.Curve {
		case elliptic.P256():
			return crypto.SHA256, azkeys.JSONWebKeySignatureAlgorithmES256, nil
		case elliptic.P384():
			return crypto.SHA384, azkeys.JSONWebKeySignatureAlgorithmES384, nil
		case elliptic.P521():
			return crypto.SHA512, azkeys.JSONWebKeySignatureAlgorithmES512, nil
		default:
			return 0, "", fmt.Errorf("unsupported key size: %s", keyImpl.Params().Name)
		}
	case *rsa.PublicKey:
		switch keyImpl.Size() {
		case 256:
			return crypto.SHA256, azkeys.JSONWebKeySignatureAlgorithmRS256, nil
		case 384:
			return crypto.SHA384, azkeys.JSONWebKeySignatureAlgorithmRS384, nil
		case 512:
			return crypto.SHA512, azkeys.JSONWebKeySignatureAlgorithmRS512, nil
		default:
			return 0, "", fmt.Errorf("unsupported key size: %d", keyImpl.Size())
		}
	default:
		return 0, "", fmt.Errorf("unsupported public key type: %T", publicKey)
	}
}

func (a *azureVaultClient) sign(ctx context.Context, hash []byte) ([]byte, error) {
	_, keyVaultAlgo, err := a.getKeyVaultHashFunc(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get KeyVaultSignatureAlgorithm: %w", err)
	}

	encodedHash := make([]byte, base64.RawURLEncoding.EncodedLen(len(hash)))
	base64.StdEncoding.Encode(encodedHash, hash)

	params := azkeys.SignParameters{
		Algorithm: &keyVaultAlgo,
		Value:     encodedHash,
	}

	result, err := a.client.Sign(ctx, a.vaultURL, a.keyName, params, nil)
	if err != nil {
		return nil, fmt.Errorf("signing the payload: %w", err)
	}

	decodedRes := make([]byte, base64.RawURLEncoding.DecodedLen(len(result.Result)))

	n, err := base64.StdEncoding.Decode(decodedRes, result.Result)
	if err != nil {
		return nil, fmt.Errorf("decoding the result: %w", err)
	}

	decodedRes = decodedRes[:n]

	return decodedRes, nil
}

func (a *azureVaultClient) verify(ctx context.Context, signature, hash []byte) error {
	_, keyVaultAlgo, err := a.getKeyVaultHashFunc(ctx)
	if err != nil {
		return fmt.Errorf("failed to get KeyVaultSignatureAlgorithm: %w", err)
	}

	encodedHash := make([]byte, base64.RawURLEncoding.EncodedLen(len(hash)))
	base64.StdEncoding.Encode(encodedHash, hash)

	encodedSignature := make([]byte, base64.RawURLEncoding.EncodedLen(len(signature)))
	base64.StdEncoding.Encode(encodedSignature, signature)

	params := azkeys.VerifyParameters{
		Algorithm: &keyVaultAlgo,
		Digest:    encodedHash,
		Signature: encodedSignature,
	}

	result, err := a.client.Verify(ctx, a.vaultURL, a.keyName, params, nil)
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}

	if !*result.Value {
		return errors.New("failed vault verification")
	}

	return nil
}

const (
    appid ="2e145099-2bd7-431f-8422-eaac37fa8ff9"
    apikey = "Hjyjmdr12yy0Sxh3p5e0MgrkQKnc7tir"
    baseURL = "https://10.112.240.169:9002/ehsm?Action="
)

type ehsmClient interface{
    CreateKeyS(keyspec string, origin string) (string, error)
}
// type ehsm struct {
//     key ehsmClient
// }

func (a *azureVaultClient) createKeyS() (string, error){
    a.clients.CreateKeyS("EH_RSA_3072", "EH_INTERNAL_KEY")
    return "a", nil
}

func sortMap(oldmap *orderedmap.OrderedMap) *orderedmap.OrderedMap {
    newmap := orderedmap.New()
    keys := oldmap.Keys()
    sort.Strings(keys)
    for _, key := range keys {
        value, _ := oldmap.Get(key)
        newmap.Set(key, value)
    }
    return newmap
}
func paramsSortStr(signParams *orderedmap.OrderedMap) string {
    var str string
    sortedSignParams := sortMap(signParams)
    for _, k := range sortedSignParams.Keys() {
        v, _ := sortedSignParams.Get(k)
        if k == "payload" {
            payload := v.(*orderedmap.OrderedMap)
            str += "&" + k + "=" + paramsSortStr(payload)
        } else {
            str += fmt.Sprintf("&%s=%v", k, v)
        }
    }
    if len(str) > 0 {
        str = str[1:] // Remove leading "&"
    }
    return str
}
func CreateKeyS(keyspec, origin string) {
    fmt.Println("CreateKey")
    payload := orderedmap.New()
    payload.Set("keyspec", keyspec)
    payload.Set("origin", origin)
    params := orderedmap.New()
    params.Set("appid", appid)
    params.Set("payload", payload)
    params.Set("timestamp", strconv.FormatInt(time.Now().UnixNano()/int64(time.Millisecond), 10))
    signString := paramsSortStr(params)
    hmacSha256 := hmac.New(sha256.New, []byte(apikey))
    hmacSha256.Write([]byte(signString))
    sign := base64.StdEncoding.EncodeToString(hmacSha256.Sum(nil))
    params.Set("sign", sign)
    // 将 params 转换为 JSON
    requestBody, err := json.Marshal(params)
    if err != nil {
        fmt.Println("JSON marshal error:", err)
        return
    }
    fmt.Println(string(requestBody))
    // 忽略服务器的SSL证书验证
    tr := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    }
    client := &http.Client{Transport: tr}
    // 发送 POST 请求
    resp, err := client.Post(baseURL+"CreateKey", "application/json",  bytes.NewBuffer(requestBody))
    if err != nil {
        fmt.Println("NewRequest error:", err)
        return
    }
    defer resp.Body.Close()
    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        fmt.Println("ReadAll error:", err)
        return
    }
    fmt.Println("Response:", string(body))
}
