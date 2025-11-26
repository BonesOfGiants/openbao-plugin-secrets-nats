package accountsync

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/rs/zerolog/log"
)

const (
	ClaimsUpdateSubject = "$SYS.REQ.CLAIMS.UPDATE"
	ClaimsDeleteSubject = "$SYS.REQ.CLAIMS.DELETE"
)

// Push accounts mechanism explained
// =================================
// General prerequsites
// ---------------------
// -> There must be a sys account and a sys account user with permissions:
// AllowPub: $SYS.REQ.CLAIMS.LIST, $SYS.REQ.CLAIMS.UPDATE, $SYS.REQ.CLAIMS.DELETE
// AllowSub: _INBOX.>
// -> open a nats connection with the JWT and SEED of this sys account user
//    with options for (optional TLS certs), timeouts, reconnect handlers, etc.

// Adding accounts:
// ----------------
// Iterate over all accounts to add and get their JWTs
// On each iteration create a PUB on subject $SYS.REQ.CLAIMS.UPDATE with the JWT as []byte
// After sending each PUB with the JWT wait for responses using SubscribeSync() within a defined time frame (e.g. 1 second). This information can be used to inform how many servers got the publish.

// Deleting accounts:
// ------------------
// Get JWT of account to be deleted
// create a PUB on subject $SYS.REQ.CLAIMS.DELETE with the JWT as []byte
// After sending the PUB with the JWT wait for responses using SubscribeSync() within a defined time frame (e.g. 1 second). This information can be used to inform how many servers got the publish.

type Config struct {
	Servers        []string
	ConnectTimeout int
	MaxReconnects  int
	ReconnectWait  int
	// Whether to continue with a deletion if the delete fails to sync to the target server
	IgnoreSyncErrorsOnDelete bool
}

type AccountSync struct {
	Config
	nc *nats.Conn
}

func NewAccountSync(syncConfig Config, o ...nats.Option) (*AccountSync, error) {
	url := strings.Join(syncConfig.Servers, ",")

	nc, err := nats.Connect(url, o...)
	if err != nil {
		return nil, err
	}

	return &AccountSync{
		Config: syncConfig,
		nc:     nc,
	}, nil
}

func (r *AccountSync) CloseConnection() {
	if r != nil {
		if r.nc != nil {
			log.Debug().Msg("sync: closing connection")
			r.nc.Close()
		}
	}
}

func (r *AccountSync) multiRequest(subject string, operation string, reqData []byte, respHandler func(srv string, data any)) int {
	ib := nats.NewInbox()
	sub, err := r.nc.SubscribeSync(ib)
	if err != nil {
		log.Error().Msgf("sync: failed to subscribe to response subject: %v", err)
		return 0
	}
	if err := r.nc.PublishRequest(subject, ib, reqData); err != nil {
		log.Error().Msgf("sync: failed to %s: %v", operation, err)
		return 0
	}
	responses := 0
	now := time.Now()
	start := now
	end := start.Add(time.Second)
	for ; end.After(now); now = time.Now() { // try with decreasing timeout until we dont get responses
		if resp, err := sub.NextMsg(end.Sub(now)); err != nil {
			if err != nats.ErrTimeout || responses == 0 {
				log.Error().Msgf("sync: failed to get response to %s: %v", operation, err)
			}
		} else if ok, srv, data := processResponse(resp); ok {
			respHandler(srv, data)
			responses++
			continue
		}
		break
	}
	return responses
}

func (r *AccountSync) DeleteAccounts(acc []string, operatorKp nkeys.KeyPair) (int, error) {

	defer operatorKp.Wipe()
	pub, err := operatorKp.PublicKey()
	if err != nil {
		return 0, err
	}

	claim := jwt.NewGenericClaims(pub)
	claim.Data["accounts"] = acc

	pruneJwt, err := claim.Encode(operatorKp)
	if err != nil {
		log.Error().Msgf("Could not encode delete request (err:%v)", err)
		return 0, err
	}
	respPrune := r.multiRequest(ClaimsDeleteSubject, "delete", []byte(pruneJwt),
		func(srv string, data any) {
			if dataMap, ok := data.(map[string]any); ok {
				log.Info().Msgf("pruned nats-server %s: %s", srv, dataMap["message"])
			} else {
				log.Info().Msgf("pruned nats-server %s: %v", srv, data)
			}
		})

	return respPrune, nil
}

func (r *AccountSync) PushAccount(accountName string, accountJWT []byte) error {
	resp := r.multiRequest(ClaimsUpdateSubject, "create", accountJWT,
		func(srv string, data any) {
			if dataMap, ok := data.(map[string]any); ok {
				log.Info().Msgf("pushed %q to nats-server %s: %s", accountName, srv, dataMap["message"])
			} else {
				log.Info().Msgf("pushed %q to nats-server %s: %v", accountName, srv, data)
			}
		})
	if resp == 0 {
		return fmt.Errorf("no response from server")
	}
	return nil
}

func processResponse(resp *nats.Msg) (bool, string, any) {
	// ServerInfo copied from nats-server, refresh as needed. Error and Data are mutually exclusive
	serverResp := struct {
		Server *struct {
			Name      string    `json:"name"`
			Host      string    `json:"host"`
			ID        string    `json:"id"`
			Cluster   string    `json:"cluster,omitempty"`
			Version   string    `json:"ver"`
			Seq       uint64    `json:"seq"`
			JetStream bool      `json:"jetstream"`
			Time      time.Time `json:"time"`
		} `json:"server"`
		Error *struct {
			Description string `json:"description"`
			Code        int    `json:"code"`
		} `json:"error"`
		Data any `json:"data"`
	}{}
	if err := json.Unmarshal(resp.Data, &serverResp); err != nil {
		log.Error().Msgf("sync: failed to parse response: %v data: %s", err, string(resp.Data))
	} else if srvName := serverResp.Server.Name; srvName == "" {
		log.Error().Msgf("sync: server responded without server name in info: %s", string(resp.Data))
	} else if err := serverResp.Error; err != nil {
		log.Error().Msgf("sync: server %s responded with error: %s", srvName, err.Description)
	} else if data := serverResp.Data; data == nil {
		log.Error().Msgf("sync: server %s responded without data: %s", srvName, string(resp.Data))
	} else {
		return true, srvName, data
	}
	return false, "", nil
}
