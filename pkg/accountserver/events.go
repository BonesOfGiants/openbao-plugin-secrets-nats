package accountserver

import (
	"fmt"
	"time"
)

// Type for our server capabilities.
type ServerCapability uint64

const (
	JetStreamEnabled     ServerCapability = 1 << iota // Server had JetStream enabled.
	BinaryStreamSnapshot                              // New stream snapshot capability.
	AccountNRG                                        // Move NRG traffic out of system account.
)

// ServerInfo identifies remote servers.
// Source: https://github.com/nats-io/nats-server/blob/4a7566f621dde8d864899a224a3293908c989ae4/server/events.go
type ServerInfo struct {
	Name     string            `json:"name"`
	Host     string            `json:"host"`
	ID       string            `json:"id"`
	Cluster  string            `json:"cluster,omitempty"`
	Domain   string            `json:"domain,omitempty"`
	Version  string            `json:"ver"`
	Tags     []string          `json:"tags,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
	// Whether JetStream is enabled (deprecated in favor of the `ServerCapability`).
	JetStream bool `json:"jetstream"`
	// Generic capability flags
	Flags ServerCapability `json:"flags"`
	// Sequence and Time from the remote server for this message.
	Seq  uint64    `json:"seq"`
	Time time.Time `json:"time"`
}

// ServerAPIClaimUpdateResponse is the response to $SYS.REQ.ACCOUNT.<id>.CLAIMS.UPDATE and $SYS.REQ.CLAIMS.UPDATE
// Source: https://github.com/nats-io/nats-server/blob/4a7566f621dde8d864899a224a3293908c989ae4/server/accounts.go
type ServerAPIClaimUpdateResponse struct {
	Server *ServerInfo        `json:"server"`
	Data   *ClaimUpdateStatus `json:"data,omitempty"`
	Error  *ClaimUpdateError  `json:"error,omitempty"`
}

// Source: https://github.com/nats-io/nats-server/blob/4a7566f621dde8d864899a224a3293908c989ae4/server/accounts.go
type ClaimUpdateError struct {
	Account     string `json:"account,omitempty"`
	Code        int    `json:"code"`
	Description string `json:"description,omitempty"`
}

func (e *ClaimUpdateError) Error() string {
	return fmt.Sprintf("claim update error for account %q: %d %s", e.Account, e.Code, e.Description)
}

// Source: https://github.com/nats-io/nats-server/blob/4a7566f621dde8d864899a224a3293908c989ae4/server/accounts.go
type ClaimUpdateStatus struct {
	Account string `json:"account,omitempty"`
	Code    int    `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}
