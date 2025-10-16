package natsbackend

import (
	"github.com/openbao/openbao/sdk/v2/framework"
)

func pathCreds(b *NatsBackend) []*framework.Path {
	paths := []*framework.Path{}
	paths = append(paths, pathUserCreds(b)...)
	return paths
}
