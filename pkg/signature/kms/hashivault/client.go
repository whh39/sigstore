//
// Copyright 2021 The Sigstore Authors.
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

// Package hashivault implement the interface with hashivault kms service
package hashivault

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
    // "strconv"
    "sort"
    "bytes"
    "github.com/iancoleman/orderedmap"
)

func init() {
	sigkms.AddProvider(ReferenceScheme, func(_ context.Context, keyResourceID string, hashFunc crypto.Hash, opts ...signature.RPCOption) (sigkms.SignerVerifier, error) {
		return LoadSignerVerifier(keyResourceID, hashFunc, opts...)
	})
}

type hashivaultClient struct {
	clients                 ehsmClient
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

func newHashivaultClient(address, token, transitSecretEnginePath, keyResourceID string, keyVersion uint64) (*hashivaultClient, error) {
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

	if transitSecretEnginePath == "" {
		transitSecretEnginePath = os.Getenv("TRANSIT_SECRET_ENGINE_PATH")
	}
	if transitSecretEnginePath == "" {
		transitSecretEnginePath = "transit"
	}

	// var clients := 

	hvClient := &hashivaultClient{
		client:                  client,
		keyPath:                 keyPath,
		transitSecretEnginePath: transitSecretEnginePath,
		keyCache: ttlcache.New[string, crypto.PublicKey](
			ttlcache.WithDisableTouchOnHit[string, crypto.PublicKey](),
		),
		keyVersion: keyVersion,
	}

	return hvClient, nil
}

func oidcLogin(_ context.Context, address, path, role, token string) (string, error) {
	fmt.Println("whh oidcLogin")
	if address == "" {
		address = os.Getenv("VAULT_ADDR")
	}
	if address == "" {
		return "", errors.New("VAULT_ADDR is not set")
	}
	if path == "" {
		path = "jwt"
	}

	client, err := vault.NewClient(&vault.Config{
		Address: address,
	})
	if err != nil {
		return "", fmt.Errorf("new vault client: %w", err)
	}

	loginData := map[string]interface{}{
		"role": role,
		"jwt":  token,
	}
	fullpath := fmt.Sprintf("auth/%s/login", path)
	resp, err := client.Logical().Write(fullpath, loginData)
	if err != nil {
		return "", fmt.Errorf("vault oidc login: %w", err)
	}
	return resp.TokenID()
}

func (h *hashivaultClient) fetchPublicKey(_ context.Context) (crypto.PublicKey, error) {
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

func (h *hashivaultClient) public() (crypto.PublicKey, error) {
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

func (h hashivaultClient) sign(digest []byte, alg crypto.Hash, opts ...signature.SignOption) ([]byte, error) {
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

func (h hashivaultClient) verify(sig, digest []byte, alg crypto.Hash, opts ...signature.VerifyOption) error {
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

func (h hashivaultClient) createKey(typeStr string) (crypto.PublicKey, error) {
	client := h.client.Logical()

	if _, err := client.Write(fmt.Sprintf("/%s/keys/%s", h.transitSecretEnginePath, h.keyPath), map[string]interface{}{
		"type": typeStr,
	}); err != nil {
		return nil, fmt.Errorf("failed to create transit key: %w", err)
	}
	return h.public()
}

const (
    appid ="2e145099-2bd7-431f-8422-eaac37fa8ff9"
    apikey = "Hjyjmdr12yy0Sxh3p5e0MgrkQKnc7tir"
    baseURL = "https://10.112.240.169:9002/ehsm?Action="
)

type ehsmClient interface{
    CreateKeyS(keyspec, origin string) (string, error)
    // CreateKeyS(keyspec string, origin string) (string, error)
}
// type ehsm struct {
//     key ehsmClient
// }

func (a hashivaultClient) createKeyS() (string, error){
	var keyspec, origin string
	keyspec = "EH_RSA_3072"
	origin = "EH_INTERNAL_KEY"
	fmt.Println("whh createKeyS")
    payload := orderedmap.New()
    payload.Set("keyspec", keyspec)
    payload.Set("origin", origin)
    params := orderedmap.New()
    // params.Set("appid", appid)
	params.Set("appid", "5534cc2e-937c-41a4-9fcb-c7f08a480a2c")
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
        return "", err
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
        return "", err
    }
    defer resp.Body.Close()
    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        fmt.Println("ReadAll error:", err)
        return "", err
    }
    fmt.Println("Response:", string(body))
    // a.clients.CreateKeyS("EH_RSA_3072", "EH_INTERNAL_KEY")
    return string(body), nil
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

// func CreateKeyS(keyspec, origin string) {
func CreateKeyS(keyspec, origin string) (string, error) {
    fmt.Println("lst CreateKey")
	return "a", nil
    // payload := orderedmap.New()
    // payload.Set("keyspec", keyspec)
    // payload.Set("origin", origin)
    // params := orderedmap.New()
    // params.Set("appid", appid)
    // params.Set("payload", payload)
    // params.Set("timestamp", strconv.FormatInt(time.Now().UnixNano()/int64(time.Millisecond), 10))
    // signString := paramsSortStr(params)
    // hmacSha256 := hmac.New(sha256.New, []byte(apikey))
    // hmacSha256.Write([]byte(signString))
    // sign := base64.StdEncoding.EncodeToString(hmacSha256.Sum(nil))
    // params.Set("sign", sign)
    // // 将 params 转换为 JSON
    // requestBody, err := json.Marshal(params)
    // if err != nil {
    //     fmt.Println("JSON marshal error:", err)
    //     return
    // }
    // fmt.Println(string(requestBody))
    // // 忽略服务器的SSL证书验证
    // tr := &http.Transport{
    //     TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    // }
    // client := &http.Client{Transport: tr}
    // // 发送 POST 请求
    // resp, err := client.Post(baseURL+"CreateKey", "application/json",  bytes.NewBuffer(requestBody))
    // if err != nil {
    //     fmt.Println("NewRequest error:", err)
    //     return
    // }
    // defer resp.Body.Close()
    // body, err := ioutil.ReadAll(resp.Body)
    // if err != nil {
    //     fmt.Println("ReadAll error:", err)
    //     return
    // }
    // fmt.Println("Response:", string(body))
}

func Enroll() {
	// 创建一个不安全的Transport
    tr := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    }

	// 创建一个不安全的Client
    client := &http.Client{Transport: tr}

    // 创建请求对象
    req, err := http.NewRequest("GET", "https://10.112.240.169:9000/ehsm?Action=Enroll", nil)
    if err != nil {
        panic(err)
    }

    // 设置请求头部
    req.Header.Set("Accept", "application/json")

    // 发送请求
    resp, err := client.Do(req)
    if err != nil {
        panic(err)
    }
    defer resp.Body.Close()

    // 读取响应内容
    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        panic(err)
    }
	fmt.Printf(string(body))

    // 解析JSON响应体
	var data map[string]interface{}
	err = json.Unmarshal(body, &data)
	if err != nil {
		panic(err)
	}

	// 输出响应体
	fmt.Printf("YYYY--%+v\n", data)
}