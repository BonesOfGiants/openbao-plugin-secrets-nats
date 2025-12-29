package accountsync

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
	SysClaimsUpdateSubject = "$SYS.REQ.CLAIMS.UPDATE"
	SysClaimsDeleteSubject = "$SYS.REQ.CLAIMS.DELETE"
)

type Config struct {
	Operator                 string
	IgnoreSyncErrorsOnDelete bool
}

type AccountSync struct {
	Config

	logger hclog.Logger
	nc     abstractnats.NatsConnection
}

type natsConn struct {
	c *nats.Conn
}

func (c *natsConn) Close() {
	c.c.Close()
}

func (c *natsConn) Servers() []string {
	return c.c.Opts.Servers
}

func (c *natsConn) SubscribeSync(subj string) (abstractnats.NatsSubscription, error) {
	return c.c.SubscribeSync(subj)
}

func (c *natsConn) PublishRequest(subj string, reply string, data []byte) error {
	return c.c.PublishRequest(subj, reply, data)
}

func NewNatsConnection(servers []string, o ...nats.Option) (abstractnats.NatsConnection, error) {
	url := strings.Join(servers, ",")

	c, err := nats.Connect(url, o...)
	if err != nil {
		return nil, err
	}

	return &natsConn{
		c: c,
	}, nil
}

func NewAccountSync(syncConfig Config, logger hclog.Logger, nc abstractnats.NatsConnection) (*AccountSync, error) {
	return &AccountSync{
		Config: syncConfig,
		logger: logger,
		nc:     nc,
	}, nil
}

func (r *AccountSync) CloseConnection() {
	if r != nil {
		if r.nc != nil {
			r.logger.Debug("sync: closing connection", "operator", r.Operator, "servers", r.nc.Servers())
			r.nc.Close()
		}
	}
}

func (r *AccountSync) claimUpdateRequest(subject string, data []byte, timeout time.Duration) error {
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
			r.logger.Debug("sync: failed to parse response", "payload", string(msg.Data))
			continue
		}

		if resp.Error != nil {
			r.logger.Warn("sync delete error", "account", resp.Error.Account, "code", resp.Error.Code, "description", resp.Error.Description)
			// todo this might be overly strict?
			return resp.Error
		} else if resp.Data != nil {
			r.logger.Trace("sync delete response", "account", resp.Data.Account, "code", resp.Data.Code, "message", resp.Data.Message)
		}
	}

	return nil
}

func (r *AccountSync) DeleteAccount(accKey nkeys.KeyPair, signingKey nkeys.KeyPair) error {
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

func (r *AccountSync) UpdateAccount(token string) error {
	err := r.claimUpdateRequest(SysClaimsUpdateSubject, []byte(token), 1*time.Second)
	if err != nil {
		return err
	}

	return nil
}
