package abstractnats

import (
	"time"

	"github.com/nats-io/nats.go"
)

type NatsSubscription interface {
	Unsubscribe() error
	NextMsg(timeout time.Duration) (*nats.Msg, error)
}

type NatsConnection interface {
	Close()
	SubscribeSync(subj string) (NatsSubscription, error)
	PublishRequest(subj string, reply string, data []byte) error
	Servers() []string
}
