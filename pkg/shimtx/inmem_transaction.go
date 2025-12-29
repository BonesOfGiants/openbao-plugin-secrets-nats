package shimtx

import (
	"context"
	"slices"
	"strings"

	"github.com/openbao/openbao/sdk/v2/logical"
)

type storageActionType int

const (
	storageActionTypePut storageActionType = iota
	storageActionTypeDelete
)

type storageAction struct {
	action storageActionType
	entry  *logical.StorageEntry
}

type inmemTransaction struct {
	s       logical.Storage
	actions []storageAction
}

// Create a new logical.Transaction that tracks Puts and Deletes in memory,
// writing to the underlying storage only when Commit is called.
func NewInmemTransaction(s logical.Storage) logical.Transaction {
	return &inmemTransaction{
		s:       s,
		actions: []storageAction{},
	}
}

func buildActionMap(path string, actions []storageAction, after string) map[string]bool {
	deletes := make(map[string]bool, len(actions))

	for _, action := range actions {
		if !strings.HasPrefix(action.entry.Key, path) {
			continue
		}

		remaining := action.entry.Key[len(path):]
		sepIdx := strings.IndexByte(remaining, '/')

		var directChildKey string
		if sepIdx == -1 {
			directChildKey = remaining
		} else {
			directChildKey = remaining[:sepIdx+1]
		}

		if directChildKey <= after {
			continue
		}

		if action.action == storageActionTypeDelete && sepIdx == -1 {
			// the direct child was deleted
			deletes[directChildKey] = true
		} else if action.action == storageActionTypePut {
			deletes[directChildKey] = false
		}
	}

	return deletes
}

// List weaves created keys into the results returned by the underlying storage backend.
func (s *inmemTransaction) List(ctx context.Context, path string) ([]string, error) {
	if len(s.actions) == 0 {
		// we have no modifications, so we can safely call List directly
		return s.s.List(ctx, path)
	}

	mods := buildActionMap(path, s.actions, "")

	if len(mods) == 0 {
		// we have no modifications, so we can safely call List directly
		return s.s.List(ctx, path)
	}

	entries, err := s.s.List(ctx, path)
	if err != nil {
		return nil, err
	}

	delta := 0
	newEntries := []string{}
	for k, v := range mods {
		if v {
			delta -= 1
		} else {
			delta += 1
			newEntries = append(newEntries, k)
		}
	}
	slices.Sort(newEntries)

	c := 0
	result := make([]string, 0, max(len(entries)+delta, 0))
	for _, entry := range entries {
		for ; c < len(newEntries); c += 1 {
			new := newEntries[c]
			if new == entry {
				// this key already exists, skip it
				continue
			} else if new > entry {
				break
			}

			result = append(result, new)
		}

		if mods[entry] {
			// key was deleted, skip it
			continue
		}

		result = append(result, entry)
	}

	if c < len(newEntries) {
		for _, entry := range newEntries[c:] {
			result = append(result, entry)
		}
	}

	return result, nil
}

// ListPage weaves created keys into the results returned by the underlying storage backend,
// respecting the after and limit arguments.
func (s *inmemTransaction) ListPage(ctx context.Context, path string, after string, limit int) ([]string, error) {
	if len(s.actions) == 0 {
		// we have no modifications, so we can safely call ListPage directly
		return s.s.ListPage(ctx, path, after, limit)
	}

	mods := buildActionMap(path, s.actions, after)

	if len(mods) == 0 {
		// we have no modifications, so we can safely call ListPage directly
		return s.s.ListPage(ctx, path, after, limit)
	}

	delCount := 0
	newEntries := []string{}
	for k, v := range mods {
		if v {
			delCount += 1
		} else {
			newEntries = append(newEntries, k)
		}
	}
	slices.Sort(newEntries)

	c := 0

	result := make([]string, 0, limit)
	currentAfter := after

	for {
		remaining := limit
		if limit > 0 {
			remaining = limit - len(result)
			remaining += delCount
		}

		page, err := s.s.ListPage(ctx, path, currentAfter, remaining)
		if err != nil {
			return nil, err
		}

		if len(page) == 0 {
			break
		}

		if c >= len(newEntries) && delCount <= 0 {
			// we're done with modifications
			result = append(result, page...)
			break
		}

		for _, entry := range page {
			tempAfter := entry
			for ; c < len(newEntries); c += 1 {
				new := newEntries[c]
				if new == entry {
					// this key already exists, skip it
					continue
				} else if new > tempAfter {
					break
				}

				result = append(result, new)
				tempAfter = new
			}

			currentAfter = entry
			if mods[entry] {
				// key was deleted, skip it
				delCount -= 1
				continue
			}
			result = append(result, entry)
		}

		if limit > 0 && len(result) >= limit {
			break
		}
	}

	result = append(result, newEntries[c:]...)

	// trim if necessary
	if limit > 0 && len(result) > limit {
		result = result[:limit]
	}

	return result, nil
}

// Get looks backward through the stored actions, and returns
// the most recent value, or nil if it's a delete.
// If not found, the value is read from the underlying storage.
func (s *inmemTransaction) Get(ctx context.Context, path string) (*logical.StorageEntry, error) {
	for _, action := range slices.Backward(s.actions) {
		if action.entry.Key == path {
			switch action.action {
			case storageActionTypeDelete:
				return nil, nil
			case storageActionTypePut:
				value := make([]byte, len(action.entry.Value))
				copy(value, action.entry.Value)
				entry := logical.StorageEntry{
					Key:      action.entry.Key,
					Value:    value,
					SealWrap: action.entry.SealWrap,
				}
				return &entry, nil
			}
		}
	}
	return s.s.Get(ctx, path)
}

// Put caches the write, to be applied to the wrapped storage upon Commit.
func (s *inmemTransaction) Put(ctx context.Context, entry *logical.StorageEntry) error {
	s.actions = append(s.actions, storageAction{
		action: storageActionTypePut,
		entry:  entry,
	})
	return nil
}

// Delete caches the deletion, to be applied to the wrapped storage upon Commit.
func (s *inmemTransaction) Delete(ctx context.Context, path string) error {
	s.actions = append(s.actions, storageAction{
		action: storageActionTypeDelete,
		entry: &logical.StorageEntry{
			Key: path,
		},
	})
	return nil
}

// Commit a transaction; this is equivalent to Rollback on a read-only
// transaction. Either Commit or Rollback must be called to release
// resources.
func (s *inmemTransaction) Commit(ctx context.Context) error {
	for _, v := range s.actions {
		switch v.action {
		case storageActionTypePut:
			err := s.s.Put(ctx, v.entry)
			if err != nil {
				return err
			}
		case storageActionTypeDelete:
			err := s.s.Delete(ctx, v.entry.Key)
			if err != nil {
				return err
			}
		}
	}
	s.actions = []storageAction{}

	return nil
}

// Rollback a transaction, preventing any changes from being persisted.
// Either Commit or Rollback must be called to release resources.
func (s *inmemTransaction) Rollback(ctx context.Context) error {
	s.actions = []storageAction{}
	return nil
}
