package natsbackend

import (
	"github.com/openbao/openbao/sdk/v2/framework"
)

func pathIssue(b *NatsBackend) []*framework.Path {
	paths := []*framework.Path{}
	paths = append(paths, pathOperatorIssue(b)...)
	paths = append(paths, pathOperatorSyncIssue(b)...)
	paths = append(paths, pathAccountIssue(b)...)
	paths = append(paths, pathAccountImportIssue(b)...)
	paths = append(paths, pathAccountRevocationIssue(b)...)
	paths = append(paths, pathUserIssue(b)...)
	paths = append(paths, pathUserGroupIssue(b)...)
	return paths
}
