package accountsync

import (
	"strings"

	"github.com/nats-io/nats.go"
)

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
