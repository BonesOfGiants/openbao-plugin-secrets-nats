package natsbackend

import (
	"context"
	"fmt"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"

	"github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/stm"
	"github.com/rs/zerolog/log"

	"github.com/nats-io/nkeys"
)

// NkeySorage represents a Nkey stored in the backend
type NKeyStorage struct {
	Seed []byte `json:"seed,omitempty"`
}

// NkeyParameters represents the parameters for a Nkey operation
type NkeyParameters struct {
	Operator string `json:"operator,omitempty"`
	Account  string `json:"account,omitempty"`
	Signing  string `json:"signing,omitempty"`
	User     string `json:"user,omitempty"`
	Seed     string `json:"seed,omitempty"`
}

// NkeyData represents the the data returned by a Nkey operation
type NkeyData struct {
	PublicKey  string `json:"publicKey,omitempty"`
	PrivateKey string `json:"privateKey,omitempty"`
	Seed       string `json:"seed,omitempty"`
}

// pathNkey extends the OpenBao API with a `/nkey/<category>`
// endpoint for the natsBackend.
func pathNkey(b *NatsBackend) []*framework.Path {
	paths := []*framework.Path{}
	paths = append(paths, pathOperatorNkey(b)...)
	paths = append(paths, pathOperatorSigningNkey(b)...)
	paths = append(paths, pathAccountNkey(b)...)
	paths = append(paths, pathAccountSigningNkey(b)...)
	paths = append(paths, pathUserNkey(b)...)
	return paths
}

// createSeed creates a new Nkey seed
func createSeed(prefix nkeys.PrefixByte) ([]byte, error) {

	// create operator keypair
	keypair, err := nkeys.CreatePair(prefix)
	if err != nil {
		return nil, err
	}

	// store seed
	seed, err := keypair.Seed()
	if err != nil {
		return nil, err
	}
	return seed, nil
}

func validateSeed(seed []byte, kind string) error {
	var expected nkeys.PrefixByte
	switch kind {
	case "operator":
		expected = nkeys.PrefixByteOperator
	case "account":
		expected = nkeys.PrefixByteAccount
	case "user":
		expected = nkeys.PrefixByteUser
	default:
		expected = nkeys.PrefixByteUnknown
	}
	prefix, _, err := nkeys.DecodeSeed(seed)
	if err != nil {
		return err
	}

	if prefix != expected {
		return fmt.Errorf("wrong seed type")
	}

	return nil
}

func readNkey(ctx context.Context, storage logical.Storage, path string) (*NKeyStorage, error) {
	return getFromStorage[NKeyStorage](ctx, storage, path)
}

func deleteNkey(ctx context.Context, storage logical.Storage, path string) error {
	return deleteFromStorage(ctx, storage, path)
}

func toNkeyData(nkey *NKeyStorage) (*NkeyData, error) {
	// convert seed into public/private key data structure
	keypair, err := nkeys.FromSeed(nkey.Seed)
	if err != nil {
		return nil, err
	}

	pub, err := keypair.PublicKey()
	if err != nil {
		return nil, err
	}

	private, err := keypair.PrivateKey()
	if err != nil {
		return nil, err
	}

	// create response
	d := &NkeyData{
		Seed:       string(nkey.Seed),
		PublicKey:  pub,
		PrivateKey: string(private),
	}
	return d, nil
}

func createResponseNkeyData(nkey *NKeyStorage) (*logical.Response, error) {

	d, err := toNkeyData(nkey)
	if err != nil {
		return nil, err
	}

	rval := map[string]any{}
	err = stm.StructToMap(d, &rval)
	if err != nil {
		return nil, err
	}

	resp := &logical.Response{
		Data: rval,
	}
	return resp, nil
}

func addNkey(ctx context.Context, storage logical.Storage, path string, prefix nkeys.PrefixByte, params NkeyParameters, kind string) error {
	nkey, err := getFromStorage[NKeyStorage](ctx, storage, path)
	if err != nil {
		return err
	}

	if nkey == nil {
		nkey = &NKeyStorage{}
	}
	if params.Seed != "" {
		nkey.Seed = []byte(params.Seed)
	}

	// when no seed is given, generate a new one
	if nkey.Seed == nil {
		log.Info().Msg("nkey does not exist. creating new one")
		nkey.Seed, err = createSeed(prefix)
		if err != nil {
			return err
		}
	} else {
		// when a seed is given, validate it
		err = validateSeed(nkey.Seed, kind)
		if err != nil {
			return err
		}
	}

	// store the nkey
	err = storeInStorage(ctx, storage, path, nkey)
	if err != nil {
		return err
	}

	return nil
}
