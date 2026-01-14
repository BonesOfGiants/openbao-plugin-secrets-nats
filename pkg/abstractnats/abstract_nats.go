package abstractnats

import (
	"strings"
	"time"

	"github.com/nats-io/nats.go"
)

type MsgHandler func(msg *Msg)

type NatsConnection interface {
	Close()
	Drain()
	Subscribe(subj string, cb MsgHandler) (NatsSubscription, error)
	SubscribeSync(subj string) (NatsSubscription, error)
	PublishRequest(subj string, reply string, data []byte) error
	Publish(subj string, data []byte) error
	Servers() []string
}

type natsConn struct {
	c *nats.Conn
}

func NewNatsConnection(servers []string, o ...nats.Option) (NatsConnection, error) {
	url := strings.Join(servers, ",")

	c, err := nats.Connect(url, o...)
	if err != nil {
		return nil, err
	}

	return &natsConn{
		c: c,
	}, nil
}

func (c *natsConn) Close() {
	c.c.Close()
}

func (c *natsConn) Drain() {
	c.c.Drain()
}

func (c *natsConn) Servers() []string {
	return c.c.Opts.Servers
}

func (c *natsConn) SubscribeSync(subj string) (NatsSubscription, error) {
	sub, err := c.c.SubscribeSync(subj)
	if err != nil {
		return nil, err
	}

	return &natsSub{
		s: sub,
	}, nil
}

func (c *natsConn) Subscribe(subj string, cb MsgHandler) (NatsSubscription, error) {
	sub, err := c.c.Subscribe(subj, func(msg *nats.Msg) {
		m := NewMsg(msg)
		m.Sub = &natsSub{
			s: msg.Sub,
		}
		cb(m)
	})
	if err != nil {
		return nil, err
	}

	return &natsSub{
		s: sub,
	}, nil
}

func (c *natsConn) PublishRequest(subj string, reply string, data []byte) error {
	return c.c.PublishRequest(subj, reply, data)
}

func (c *natsConn) Publish(subj string, data []byte) error {
	return c.c.Publish(subj, data)
}

type NatsSubscription interface {
	Connection() NatsConnection
	Unsubscribe() error
	NextMsg(timeout time.Duration) (*Msg, error)
}

type natsSub struct {
	nc *natsConn
	s  *nats.Subscription
}

func (s *natsSub) Connection() NatsConnection {
	return s.nc
}

func (s *natsSub) NextMsg(timeout time.Duration) (*Msg, error) {
	var msg *Msg
	m, err := s.s.NextMsg(timeout)
	if err != nil {
		return msg, err
	}

	msg = &Msg{
		Subject: m.Subject,
		Reply:   m.Reply,
		Header:  m.Header,
		Data:    m.Data,
		Sub:     s,
	}

	return msg, nil
}

func (s *natsSub) Unsubscribe() error {
	return s.s.Unsubscribe()
}

type Msg struct {
	Subject string
	Reply   string
	Header  nats.Header
	Data    []byte
	Sub     NatsSubscription
}

func NewMsg(m *nats.Msg) *Msg {
	return &Msg{
		Subject: m.Subject,
		Reply:   m.Reply,
		Header:  m.Header,
		Data:    m.Data,
	}
}

func (m *Msg) Respond(data []byte) error {
	if m == nil || m.Sub == nil {
		return nats.ErrMsgNotBound
	}
	if m.Reply == "" {
		return nats.ErrMsgNoReply
	}
	nc := m.Sub.Connection()
	return nc.Publish(m.Reply, data)
}
