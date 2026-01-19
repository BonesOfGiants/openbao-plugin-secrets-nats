package accountserver

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/abstractnats"
	"github.com/hashicorp/go-hclog"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

const (
	SysClaimsUpdateSubject        = "$SYS.REQ.CLAIMS.UPDATE"
	SysClaimsDeleteSubject        = "$SYS.REQ.CLAIMS.DELETE"
	SysAccountClaimsLookupSubject = "$SYS.REQ.ACCOUNT.*.CLAIMS.LOOKUP"
	accLookupReqTokens            = 6
	accReqAccIndex                = 3
)

type Config struct {
	Operator             string
	EnableAccountLookups bool
	EnableAccountUpdates bool
	EnableAccountDeletes bool
}

type JwtLookupFunc func(id string) (string, error)
type AccountServer struct {
	Config

	lookup JwtLookupFunc
	logger hclog.Logger
	nc     abstractnats.NatsConnection
}

func NewAccountServer(cfg Config, lookupFunc JwtLookupFunc, logger hclog.Logger, nc abstractnats.NatsConnection) (*AccountServer, error) {
	server := &AccountServer{
		Config: cfg,
		lookup: lookupFunc,
		logger: logger,
		nc:     nc,
	}

	if cfg.EnableAccountLookups {
		_, err := nc.Subscribe(SysAccountClaimsLookupSubject, server.accountLookupRequest)
		if err != nil {
			return nil, err
		}
	}

	return server, nil
}

func (r *AccountServer) CloseConnection() {
	if r != nil {
		if r.nc != nil {
			r.logger.Debug("account server: closing connection", "operator", r.Operator, "servers", r.nc.Servers())
			r.nc.Drain()
		}
	}
}

func (r *AccountServer) accountLookupRequest(msg *abstractnats.Msg) {
	tk := strings.Split(msg.Subject, ".")
	if len(tk) != accLookupReqTokens {
		return
	}

	acc := tk[accReqAccIndex]
	jwt, err := r.lookup(acc)
	if err != nil {
		r.logger.Debug("account server: failed to lookup jwt", "operator", r.Operator, "id", acc, "error", err)
		// todo update the config
	}

	// if the jwt is not found "" will be returned. An empty response is valid to signal absence of a jwt.
	err = msg.Respond([]byte(jwt))
	if err != nil {
		r.logger.Debug("account server: error returning jwt lookup", "operator", r.Operator, "id", acc, "error", err)
	}
}

func (r *AccountServer) claimUpdateRequest(subject string, data []byte, timeout time.Duration) error {
	ib := nats.NewInbox()
	sub, err := r.nc.SubscribeSync(ib)
	if err != nil {
		return err
	}
	defer sub.Unsubscribe()

	err = r.nc.PublishRequest(subject, ib, data)
	if err != nil {
		return err
	}

	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		msg, err := sub.NextMsg(time.Until(deadline))
		if err == nats.ErrTimeout {
			break
		}

		if err != nil {
			return err
		}

		var resp ServerAPIClaimUpdateResponse
		err = json.Unmarshal(msg.Data, &resp)
		if err != nil {
			r.logger.Debug("account server request error: failed to parse response", "subject", subject, "payload", string(msg.Data))
			continue
		}

		if resp.Error != nil {
			r.logger.Warn("account server request error: response error", "subject", subject, "account", resp.Error.Account, "code", resp.Error.Code, "description", resp.Error.Description)
			// todo this might be overly strict?
			return resp.Error
		} else if resp.Data != nil {
			r.logger.Trace("account server request success:", "subject", subject, "account", resp.Data.Account, "code", resp.Data.Code, "message", resp.Data.Message)
		}
	}

	return nil
}

func (r *AccountServer) DeleteAccount(accKey nkeys.KeyPair, signingKey nkeys.KeyPair) error {
	if !r.EnableAccountDeletes {
		return nil
	}

	subject, err := signingKey.PublicKey()
	if err != nil {
		return err
	}

	accSubj, err := accKey.PublicKey()
	if err != nil {
		return err
	}

	claim := jwt.NewGenericClaims(subject)
	claim.Data["accounts"] = []string{accSubj}

	token, err := claim.Encode(signingKey)
	if err != nil {
		return err
	}

	err = r.claimUpdateRequest(SysClaimsDeleteSubject, []byte(token), 1*time.Second)
	if err != nil {
		return err
	}

	return nil
}

func (r *AccountServer) UpdateAccount(token string) error {
	if !r.EnableAccountUpdates {
		return nil
	}

	err := r.claimUpdateRequest(SysClaimsUpdateSubject, []byte(token), 1*time.Second)
	if err != nil {
		return err
	}

	return nil
}
