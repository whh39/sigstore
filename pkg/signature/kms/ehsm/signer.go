package ehsm

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

// Taken from https://www.vaultproject.io/api/secret/transit
// nolint:revive
const (
	AlgorithmEHRSA4096 = "EH_RSA_4096"
	AlgorithmEHRSA3072 = "EH_RSA_3072"
	AlgorithmEHRSA2048 = "EH_RSA_2048"
	AlgorithmEHECP256   = "EH_EC_P256"
	AlgorithmEHECP224   = "EH_EC_P224"
	AlgorithmEHECP384   = "EH_EC_P384"
	AlgorithmEHECP521   = "EH_EC_P521"
	AlgorithmEMSM2   = "EH_SM2"
)

var ehsmSupportedAlgorithms = []string{
	AlgorithmEHRSA4096,
	AlgorithmEHRSA3072,
	AlgorithmEHRSA2048,
	AlgorithmEHECP256,
	AlgorithmEHECP224,
	AlgorithmEHECP384,
	AlgorithmEHECP521,
	AlgorithmEMSM2,
}

var ehsmSupportedHashFuncs = []crypto.Hash{
	crypto.SHA224,
	crypto.SHA256,
	crypto.SHA384,
	crypto.SHA512,
	crypto.Hash(0),
}

// SignerVerifier creates and verifies digital signatures over a message using EHSM KMS service
type SignerVerifier struct {
	hashFunc crypto.Hash
	client   *ehsmClient
}

// LoadSignerVerifier generates signatures using the specified key object in Vault and hash algorithm.
//
// It also can verify signatures (via a remote vall to the Vault instance). hashFunc should be
// set to crypto.Hash(0) if the key referred to by referenceStr is an ED25519 signing key.
func LoadSignerVerifier(referenceStr string, hashFunc crypto.Hash, opts ...signature.RPCOption) (*SignerVerifier, error) {
	h := &SignerVerifier{}
	ctx := context.Background()
	rpcAuth := options.RPCAuth{}
	var keyVersion string
	for _, opt := range opts {
		opt.ApplyRPCAuthOpts(&rpcAuth)
		opt.ApplyContext(&ctx)
		opt.ApplyKeyVersion(&keyVersion)
	}

	var keyVersionUint uint64
	var err error
	if keyVersion != "" {
		keyVersionUint, err = strconv.ParseUint(keyVersion, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parsing key version: %w", err)
		}
	}

	h.client, err = newEhsmClient(rpcAuth.Address, rpcAuth.Token, rpcAuth.Path, referenceStr, keyVersionUint)
	if err != nil {
		return nil, err
	}

	switch hashFunc {
	case 0, crypto.SHA224, crypto.SHA256, crypto.SHA384, crypto.SHA512:
		h.hashFunc = hashFunc
	default:
		return nil, errors.New("hash function not supported by Ehsm")
	}

	return h, nil
}

// SignMessage signs the provided message using HashiCorp Vault KMS. If the message is provided,
// this method will compute the digest according to the hash function specified
// when the HashivaultSigner was created.
//
// SignMessage recognizes the following Options listed in order of preference:
//
// - WithDigest()
//
// All other options are ignored if specified.
func (h SignerVerifier) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {
	var digest []byte
	var signerOpts crypto.SignerOpts = h.hashFunc

	for _, opt := range opts {
		opt.ApplyDigest(&digest)
		opt.ApplyCryptoSignerOpts(&signerOpts)
	}

	digest, hf, err := signature.ComputeDigestForSigning(message, signerOpts.HashFunc(), ehsmSupportedHashFuncs, opts...)
	if err != nil {
		return nil, err
	}

	return h.client.sign(digest, hf, opts...)
}

// PublicKey returns the public key that can be used to verify signatures created by
// this signer. All options provided in arguments to this method are ignored.
func (h SignerVerifier) PublicKey(_ ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	return h.client.fetchPublicKey()
}

// VerifySignature verifies the signature for the given message. Unless provided
// in an option, the digest of the message will be computed using the hash function specified
// when the SignerVerifier was created.
//
// This function returns nil if the verification succeeded, and an error message otherwise.
//
// This function recognizes the following Options listed in order of preference:
//
// - WithDigest()
//
// - WithCryptoSignerOpts()
//
// All other options are ignored if specified.
func (h SignerVerifier) VerifySignature(sig, message io.Reader, opts ...signature.VerifyOption) error {
	var digest []byte
	var signerOpts crypto.SignerOpts = h.hashFunc

	for _, opt := range opts {
		opt.ApplyDigest(&digest)
		opt.ApplyCryptoSignerOpts(&signerOpts)
	}

	digest, hf, err := signature.ComputeDigestForVerifying(message, signerOpts.HashFunc(), ehsmSupportedHashFuncs, opts...)
	if err != nil {
		return err
	}

	sigBytes, err := io.ReadAll(sig)
	if err != nil {
		return fmt.Errorf("reading signature: %w", err)
	}

	return h.client.verify(sigBytes, digest, hf, opts...)
}

// CreateKey attempts to create a new key in Vault with the specified algorithm.
func (h SignerVerifier) CreateKey(_ context.Context, algorithm string) (crypto.PublicKey, error) {
	return h.client.createKey(algorithm)
}

type cryptoSignerWrapper struct {
	ctx      context.Context
	hashFunc crypto.Hash
	sv       *SignerVerifier
	errFunc  func(error)
}

func (c cryptoSignerWrapper) Public() crypto.PublicKey {
	pk, err := c.sv.PublicKey(options.WithContext(c.ctx))
	if err != nil && c.errFunc != nil {
		c.errFunc(err)
	}
	return pk
}

func (c cryptoSignerWrapper) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	hashFunc := c.hashFunc
	if opts != nil {
		hashFunc = opts.HashFunc()
	}
	hvOptions := []signature.SignOption{
		options.WithContext(c.ctx),
		options.WithDigest(digest),
		options.WithCryptoSignerOpts(hashFunc),
	}

	return c.sv.SignMessage(nil, hvOptions...)
}

// CryptoSigner returns a crypto.Signer object that uses the underlying SignerVerifier, along with a crypto.SignerOpts object
// that allows the KMS to be used in APIs that only accept the standard golang objects
func (h *SignerVerifier) CryptoSigner(ctx context.Context, errFunc func(error)) (crypto.Signer, crypto.SignerOpts, error) {
	csw := &cryptoSignerWrapper{
		ctx:      ctx,
		sv:       h,
		hashFunc: h.hashFunc,
		errFunc:  errFunc,
	}

	return csw, h.hashFunc, nil
}

// SupportedAlgorithms returns the list of algorithms supported by the EHSM service
func (*SignerVerifier) SupportedAlgorithms() []string {
	return ehsmSupportedAlgorithms
}

// DefaultAlgorithm returns the default algorithm for the EHSM service
func (*SignerVerifier) DefaultAlgorithm() string {
	return AlgorithmEHECP256
}
