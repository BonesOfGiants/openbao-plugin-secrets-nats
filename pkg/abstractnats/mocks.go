package abstractnats

import (
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/stretchr/testify/assert"
)

type MockNatsConnection interface {
	NatsConnection

	ValidateConnection(servers []string, o ...nats.Option) (NatsConnection, error)
	ExpectInboxSubscription() MockNatsSubscription
	ExpectSubscription(subj string) MockNatsSubscription
	ExpectPublish(subj string, handler PublishHandler)
}

type MockNatsSubscription interface {
	NatsSubscription

	Subject() string
	Reply(reply string, data []byte)
	Publish(subject, reply string, data []byte)
	Unsubscribed() bool
}

type mockNatsSubscription struct {
	unsubscribed bool
	subject      string
	messages     []*Msg
	m            *mockNats
}

func (m *mockNatsSubscription) Connection() NatsConnection {
	return m.m
}

func (m *mockNatsSubscription) Subject() string {
	return m.subject
}

func (m *mockNatsSubscription) Unsubscribed() bool {
	return m.unsubscribed
}

type PublishHandler func(m MockNatsConnection, subj string, reply string, data []byte) error

type mockNats struct {
	closed            bool
	subs              map[string]*mockNatsSubscription
	expectedPublishes map[string]PublishHandler
	expectedSubs      map[string]*mockNatsSubscription
	expectedInboxSubs []*mockNatsSubscription
	tb                testing.TB
}

func NewMock(tb testing.TB) MockNatsConnection {
	m := &mockNats{
		tb:                tb,
		subs:              map[string]*mockNatsSubscription{},
		expectedPublishes: map[string]PublishHandler{},
		expectedSubs:      map[string]*mockNatsSubscription{},
		expectedInboxSubs: []*mockNatsSubscription{},
	}

	m.tb.Cleanup(m.cleanup)
	return m
}

func (m *mockNats) ExpectPublish(subj string, handler PublishHandler) {
	m.tb.Helper()

	m.expectedPublishes[subj] = handler
}

func (m *mockNats) ExpectSubscription(subj string) MockNatsSubscription {
	m.tb.Helper()

	sub := m.newNatsMockSubscription(subj)

	m.expectedSubs[subj] = sub

	return sub
}

func (m *mockNats) ExpectInboxSubscription() MockNatsSubscription {
	m.tb.Helper()

	sub := m.newNatsMockSubscription("")

	m.expectedInboxSubs = append(m.expectedInboxSubs, sub)

	return sub
}

func (m *mockNats) AssertClosed() {
	m.tb.Helper()

	assert.Equal(m.tb, true, m.closed)
}

func (m *mockNats) ValidateConnection(servers []string, o ...nats.Option) (NatsConnection, error) {
	m.tb.Helper()

	// todo add asserts on the options we expect to see

	return m, nil
}

func (s *mockNatsSubscription) Unsubscribe() error {
	s.unsubscribed = true
	return nil
}

func (s *mockNatsSubscription) NextMsg(timeout time.Duration) (*Msg, error) {
	s.m.tb.Helper()

	if len(s.messages) > 0 {
		msg := s.messages[0]
		s.messages = s.messages[1:]
		return msg, nil
	} else {
		// for now, immediately time out
		return nil, nats.ErrTimeout
	}
}

// Enqueue a message as if it's a publish from the server to the client.
func (s *mockNatsSubscription) Publish(subject string, reply string, data []byte) {
	msg := &Msg{
		Subject: subject,
		Reply:   reply,
		Data:    data,
		Sub:     s,
	}
	s.messages = append(s.messages, msg)
}

// Enqueue a message as if it's a reply from the server to the client.
func (s *mockNatsSubscription) Reply(reply string, data []byte) {
	msg := &Msg{
		Subject: s.subject,
		Reply:   reply,
		Data:    data,
		Sub:     s,
	}
	s.messages = append(s.messages, msg)
}

func (m *mockNats) Close() {
	m.closed = true
}

func (m *mockNats) Drain() {
	m.closed = true
}

func (m *mockNats) Subscribe(subj string, cb MsgHandler) (NatsSubscription, error) {
	m.tb.Helper()

	if strings.HasPrefix(subj, "_INBOX") {
		if len(m.expectedInboxSubs) > 0 {
			sub := m.expectedInboxSubs[0]
			sub.subject = subj
			m.expectedInboxSubs = m.expectedInboxSubs[1:]

			for _, v := range sub.messages {
				cb(v)
			}
			return sub, nil
		}
	} else {
		if sub, ok := m.expectedSubs[subj]; ok {
			delete(m.expectedSubs, subj)
			for _, v := range sub.messages {
				cb(v)
			}
			return sub, nil
		}
	}

	assert.Fail(m.tb, "unexpected subscribe", subj)
	return nil, nil
}

func (m *mockNats) SubscribeSync(subj string) (NatsSubscription, error) {
	m.tb.Helper()

	if strings.HasPrefix(subj, "_INBOX") {
		if len(m.expectedInboxSubs) > 0 {
			sub := m.expectedInboxSubs[0]
			sub.subject = subj
			m.expectedInboxSubs = m.expectedInboxSubs[1:]
			return sub, nil
		}
	} else {
		delete(m.expectedSubs, subj)
		if sub, ok := m.expectedSubs[subj]; ok {
			return sub, nil
		}
	}

	assert.Fail(m.tb, "unexpected subscribe", subj)
	return nil, nil
}

func (m *mockNats) Publish(subj string, data []byte) error {
	m.tb.Helper()

	if h, ok := m.expectedPublishes[subj]; ok {
		delete(m.expectedPublishes, subj)
		return h(m, subj, "", data)
	}

	assert.Failf(m.tb, "unexpected publish", "subject: %q, data: %q", subj, string(data))
	return nil
}

func (m *mockNats) PublishRequest(subj string, reply string, data []byte) error {
	m.tb.Helper()

	if h, ok := m.expectedPublishes[subj]; ok {
		delete(m.expectedPublishes, subj)
		return h(m, subj, reply, data)
	}

	assert.FailNowf(m.tb, "unexpected publish", "subject: %q, reply: %q, data: %q", subj, reply, string(data))
	return nil
}

func (m *mockNats) Servers() []string {
	return []string{"nats://localhost:4222"}
}

func (m *mockNats) newNatsMockSubscription(subject string) *mockNatsSubscription {
	return &mockNatsSubscription{
		messages: []*Msg{},
		subject:  subject,
		m:        m,
	}
}

func (m *mockNats) cleanup() {
	if len(m.expectedInboxSubs) > 0 {
		assert.Failf(m.tb, "lingering inbox subs", "%d inbox subs remaining at the end of the test", len(m.expectedInboxSubs))
	}
	if len(m.expectedPublishes) > 0 {
		assert.Failf(m.tb, "lingering requests", "%d requests remaining at the end of the test: %+v", len(m.expectedPublishes), slices.Collect(maps.Keys(m.expectedPublishes)))
	}
	if len(m.expectedSubs) > 0 {
		assert.Failf(m.tb, "lingering subs", "%d subs remaining at the end of the test: %+v", len(m.expectedSubs), slices.Collect(maps.Keys(m.expectedSubs)))
	}
}
