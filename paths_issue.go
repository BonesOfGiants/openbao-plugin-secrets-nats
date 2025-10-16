package natsbackend

import (
	"context"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func pathIssue(b *NatsBackend) []*framework.Path {
	paths := []*framework.Path{}
	paths = append(paths, pathOperatorIssue(b)...)
	paths = append(paths, pathAccountIssue(b)...)
	paths = append(paths, pathAccountImportIssue(b)...)
	paths = append(paths, pathAccountRevocationIssue(b)...)
	paths = append(paths, pathUserIssue(b)...)
	return paths
}

func listIssues(ctx context.Context, storage logical.Storage, path string) ([]string, error) {
	l, err := storage.List(ctx, path)
	if err != nil {
		return nil, err
	}
	var issues []string
	for _, v := range l {
		if v != "/" {
			issues = append(issues, v)
		}
	}
	return issues, nil
}
