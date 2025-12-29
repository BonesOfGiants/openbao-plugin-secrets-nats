package shimtx_test

import (
	"context"
	"testing"

	"github.com/bonesofgiants/openbao-plugin-secrets-nats/pkg/shimtx"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type transactionTestAction interface {
	exec(ctx context.Context, s logical.Storage) error
}

type transactionTestPut struct {
	key   string
	value string
}

func NewTestPut(key, value string) transactionTestAction {
	return &transactionTestPut{key: key, value: value}
}

func (a *transactionTestPut) exec(ctx context.Context, s logical.Storage) error {
	return s.Put(ctx, &logical.StorageEntry{
		Key:   a.key,
		Value: []byte(a.value),
	})
}

type transactionTestDelete struct {
	key string
}

func NewTestDelete(key string) transactionTestAction {
	return &transactionTestDelete{key: key}
}

func (a *transactionTestDelete) exec(ctx context.Context, s logical.Storage) error {
	return s.Delete(ctx, a.key)
}

type transactionTestAssert struct {
	key   string
	value *logical.StorageEntry
}

func NewTestAssertValue(key string, value string) transactionTestAssert {
	return transactionTestAssert{
		key: key,
		value: &logical.StorageEntry{
			Key:   key,
			Value: []byte(value),
		},
	}
}

func NewTestAssertNotExists(key string) transactionTestAssert {
	return transactionTestAssert{
		key:   key,
		value: nil,
	}
}

func TestFallbackTransaction_PutDelete(t *testing.T) {
	cases := []struct {
		name           string
		preTransaction []transactionTestAction
		inTransaction  []transactionTestAction
		asserts        []transactionTestAssert
	}{
		{
			name: "not_cached_existing",

			preTransaction: []transactionTestAction{
				NewTestPut("test/key", "value"),
			},
			asserts: []transactionTestAssert{
				NewTestAssertValue("test/key", "value"),
			},
		},
		{
			name: "not_cached_non_existant",

			preTransaction: []transactionTestAction{},
			asserts: []transactionTestAssert{
				NewTestAssertNotExists("test/key"),
			},
		},
		{
			name: "simple_put",

			inTransaction: []transactionTestAction{
				NewTestPut("test/key", "value"),
			},
			asserts: []transactionTestAssert{
				NewTestAssertValue("test/key", "value"),
			},
		},
		{
			name: "simple_delete",
			preTransaction: []transactionTestAction{
				NewTestPut("test/key", "value"),
			},
			inTransaction: []transactionTestAction{
				NewTestDelete("test/key"),
			},
			asserts: []transactionTestAssert{
				NewTestAssertNotExists("test/key"),
			},
		},
		{
			name: "put_then_delete",

			preTransaction: []transactionTestAction{},
			inTransaction: []transactionTestAction{
				NewTestPut("test/key", "value"),
				NewTestDelete("test/key"),
			},
			asserts: []transactionTestAssert{
				NewTestAssertNotExists("test/key"),
			},
		},
		{
			name: "delete_then_put",

			preTransaction: []transactionTestAction{},
			inTransaction: []transactionTestAction{
				NewTestDelete("test/key"),
				NewTestPut("test/key", "value"),
			},
			asserts: []transactionTestAssert{
				NewTestAssertValue("test/key", "value"),
			},
		},
		{
			name: "stacked_puts",

			preTransaction: []transactionTestAction{},
			inTransaction: []transactionTestAction{
				NewTestPut("test/key", "value1"),
				NewTestPut("test/key", "value2"),
			},
			asserts: []transactionTestAssert{
				NewTestAssertValue("test/key", "value2"),
			},
		},
		{
			name: "multiple_keys",

			preTransaction: []transactionTestAction{
				NewTestPut("test/key1", "value1"),
				NewTestPut("test/key2", "value2"),
			},
			inTransaction: []transactionTestAction{
				NewTestPut("test/key1", "value1_new"),
				NewTestPut("test/key/subkey", "value_subkey"),
			},
			asserts: []transactionTestAssert{
				NewTestAssertValue("test/key1", "value1_new"),
				NewTestAssertValue("test/key2", "value2"),
				NewTestAssertValue("test/key/subkey", "value_subkey"),
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			storage := &logical.InmemStorage{}
			ctx := context.Background()
			for _, action := range tc.preTransaction {
				action.exec(ctx, storage)
			}

			txn := shimtx.NewInmemTransaction(storage)

			for _, action := range tc.inTransaction {
				action.exec(ctx, txn)
			}

			for _, cmp := range tc.asserts {
				entry, err := txn.Get(ctx, cmp.key)
				assert.NoError(t, err)

				assert.EqualValues(t, cmp.value, entry)
			}
		})
	}
}

func TestFallbackTransaction_List(t *testing.T) {
	cases := []struct {
		name           string
		path           string
		preTransaction []transactionTestAction
		inTransaction  []transactionTestAction
		expected       []string
	}{
		{
			name: "pre_transaction",

			path: "test/",
			preTransaction: []transactionTestAction{
				NewTestPut("test/a", "value"),
				NewTestPut("test/b", "value"),
				NewTestPut("test/c", "value"),
			},
			expected: []string{
				"a",
				"b",
				"c",
			},
		},
		{
			name: "in_transaction",

			path: "test/",
			inTransaction: []transactionTestAction{
				NewTestPut("test/a", "value"),
				NewTestPut("test/b", "value"),
				NewTestPut("test/c", "value"),
			},
			expected: []string{
				"a",
				"b",
				"c",
			},
		},
		{
			name: "mixed_put",

			path: "test/",
			preTransaction: []transactionTestAction{
				NewTestPut("test/a", "value"),
				NewTestPut("test/c", "value"),
				NewTestPut("test/e", "value"),
			},
			inTransaction: []transactionTestAction{
				NewTestPut("test/b", "value"),
				NewTestPut("test/d", "value"),
				NewTestPut("test/f", "value"),
			},
			expected: []string{
				"a",
				"b",
				"c",
				"d",
				"e",
				"f",
			},
		},
		{
			name: "delete_non_existant",

			path: "test/",
			inTransaction: []transactionTestAction{
				NewTestDelete("test/c"),
			},
			expected: []string{},
		},
		{
			name: "simple_delete",

			path: "test/",
			preTransaction: []transactionTestAction{
				NewTestPut("test/a", "value"),
				NewTestPut("test/c", "value"),
				NewTestPut("test/e", "value"),
			},
			inTransaction: []transactionTestAction{
				NewTestDelete("test/c"),
			},
			expected: []string{
				"a",
				"e",
			},
		},
		{
			name: "mixed_put_delete",

			path: "test/",
			preTransaction: []transactionTestAction{
				NewTestPut("test/a", "value"),
				NewTestPut("test/b", "value"),
				NewTestPut("test/c", "value"),
			},
			inTransaction: []transactionTestAction{
				NewTestPut("test/d", "value"),
				NewTestDelete("test/c"),
				NewTestPut("test/e", "value"),
				NewTestPut("test/f", "value"),
				NewTestDelete("test/e"),
			},
			expected: []string{
				"a",
				"b",
				"d",
				"f",
			},
		},
		{
			name: "shadowed_put",

			path: "test/",
			preTransaction: []transactionTestAction{
				NewTestPut("test/a", "value"),
				NewTestPut("test/b", "value"),
				NewTestPut("test/c", "value"),
			},
			inTransaction: []transactionTestAction{
				NewTestPut("test/d", "value"),
				NewTestDelete("test/d"),
			},
			expected: []string{
				"a",
				"b",
				"c",
			},
		},
		{
			name: "shadowed_delete",

			path: "test/",
			preTransaction: []transactionTestAction{
				NewTestPut("test/a", "value"),
				NewTestPut("test/b", "value"),
				NewTestPut("test/c", "value"),
			},
			inTransaction: []transactionTestAction{
				NewTestDelete("test/c"),
				NewTestPut("test/c", "value"),
			},
			expected: []string{
				"a",
				"b",
				"c",
			},
		},
		{
			name: "subkey",

			path: "test/",
			preTransaction: []transactionTestAction{
				NewTestPut("test/a", "value"),
				NewTestPut("test/b", "value"),
				NewTestPut("test/c", "value"),
			},
			inTransaction: []transactionTestAction{
				NewTestPut("test/c/subkey", "value"),
			},
			expected: []string{
				"a",
				"b",
				"c",
				"c/",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			storage := &logical.InmemStorage{}
			ctx := context.Background()
			for _, action := range tc.preTransaction {
				action.exec(ctx, storage)
			}

			txn := shimtx.NewInmemTransaction(storage)

			for _, action := range tc.inTransaction {
				action.exec(ctx, txn)
			}

			entries, err := txn.List(ctx, tc.path)
			assert.NoError(t, err)

			assert.Equal(t, tc.expected, entries)
		})
	}
}

func TestFallbackTransaction_ListPage(t *testing.T) {
	cases := []struct {
		name           string
		path           string
		preTransaction []transactionTestAction
		inTransaction  []transactionTestAction
		after          string
		limit          int
		expected       [][]string
	}{
		{
			name: "pre_transaction",

			path: "test/",
			preTransaction: []transactionTestAction{
				NewTestPut("test/a", "value"),
				NewTestPut("test/b", "value"),
				NewTestPut("test/c", "value"),
			},
			expected: [][]string{
				{"a", "b", "c"},
			},
		},
		{
			name: "in_transaction",

			path: "test/",
			inTransaction: []transactionTestAction{
				NewTestPut("test/a", "value"),
				NewTestPut("test/b", "value"),
				NewTestPut("test/c", "value"),
			},
			expected: [][]string{
				{"a", "b", "c"},
			},
		},
		{
			name: "mixed_put",

			path: "test/",
			preTransaction: []transactionTestAction{
				NewTestPut("test/a", "value"),
				NewTestPut("test/c", "value"),
				NewTestPut("test/e", "value"),
			},
			inTransaction: []transactionTestAction{
				NewTestPut("test/b", "value"),
				NewTestPut("test/d", "value"),
				NewTestPut("test/f", "value"),
			},
			expected: [][]string{
				{
					"a",
					"b",
					"c",
					"d",
					"e",
					"f",
				},
			},
		},
		{
			name: "delete_non_existant",

			path: "test/",
			inTransaction: []transactionTestAction{
				NewTestDelete("test/c"),
			},
			expected: [][]string{},
		},
		{
			name: "simple_delete",

			path: "test/",
			preTransaction: []transactionTestAction{
				NewTestPut("test/a", "value"),
				NewTestPut("test/c", "value"),
				NewTestPut("test/e", "value"),
			},
			inTransaction: []transactionTestAction{
				NewTestDelete("test/c"),
			},
			expected: [][]string{
				{
					"a",
					"e",
				},
			},
		},
		{
			name: "mixed_put_delete",

			path: "test/",
			preTransaction: []transactionTestAction{
				NewTestPut("test/a", "value"),
				NewTestPut("test/b", "value"),
				NewTestPut("test/c", "value"),
			},
			inTransaction: []transactionTestAction{
				NewTestPut("test/d", "value"),
				NewTestDelete("test/c"),
				NewTestPut("test/e", "value"),
				NewTestPut("test/f", "value"),
				NewTestDelete("test/e"),
			},
			expected: [][]string{
				{
					"a",
					"b",
					"d",
					"f",
				},
			},
		},
		{
			name: "shadowed_put",

			path: "test/",
			preTransaction: []transactionTestAction{
				NewTestPut("test/a", "value"),
				NewTestPut("test/b", "value"),
				NewTestPut("test/c", "value"),
			},
			inTransaction: []transactionTestAction{
				NewTestPut("test/d", "value"),
				NewTestDelete("test/d"),
			},
			expected: [][]string{
				{
					"a",
					"b",
					"c",
				},
			},
		},
		{
			name: "shadowed_delete",

			path: "test/",
			preTransaction: []transactionTestAction{
				NewTestPut("test/a", "value"),
				NewTestPut("test/b", "value"),
				NewTestPut("test/c", "value"),
			},
			inTransaction: []transactionTestAction{
				NewTestDelete("test/c"),
				NewTestPut("test/c", "value"),
			},
			expected: [][]string{
				{
					"a",
					"b",
					"c",
				},
			},
		},
		{
			name: "subkey",

			path: "test/",
			preTransaction: []transactionTestAction{
				NewTestPut("test/a", "value"),
				NewTestPut("test/b", "value"),
				NewTestPut("test/c", "value"),
			},
			inTransaction: []transactionTestAction{
				NewTestPut("test/c/subkey", "value"),
			},
			expected: [][]string{
				{
					"a",
					"b",
					"c",
					"c/",
				},
			},
		},
		{
			name: "multi_page",

			path:  "test/",
			limit: 3,
			preTransaction: []transactionTestAction{
				NewTestPut("test/b", "value"),
				NewTestPut("test/c", "value"),
				NewTestPut("test/e", "value"),
				NewTestPut("test/f", "value"),
			},
			inTransaction: []transactionTestAction{
				NewTestPut("test/d", "value"),
				NewTestPut("test/a", "value"),
				NewTestPut("test/g", "value"),
			},
			expected: [][]string{
				{
					"a",
					"b",
					"c",
				},
				{
					"d",
					"e",
					"f",
				},
				{
					"g",
				},
			},
		},
		{
			name: "multi_page_after",

			path:  "test/",
			after: "d",
			limit: 3,
			preTransaction: []transactionTestAction{
				NewTestPut("test/b", "value"),
				NewTestPut("test/c", "value"),
				NewTestPut("test/e", "value"),
				NewTestPut("test/f", "value"),
			},
			inTransaction: []transactionTestAction{
				NewTestPut("test/d", "value"),
				NewTestPut("test/a", "value"),
				NewTestPut("test/g", "value"),
			},
			expected: [][]string{
				{
					"e",
					"f",
					"g",
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			storage := &logical.InmemStorage{}
			ctx := context.Background()
			for _, action := range tc.preTransaction {
				action.exec(ctx, storage)
			}

			txn := shimtx.NewInmemTransaction(storage)

			for _, action := range tc.inTransaction {
				action.exec(ctx, txn)
			}

			after := tc.after
			for _, expected := range tc.expected {
				entries, err := txn.ListPage(ctx, tc.path, after, tc.limit)
				assert.NoError(t, err)

				assert.Equal(t, expected, entries)

				if len(entries) == 0 {
					break
				}
				after = entries[len(entries)-1]
			}
		})
	}
}

func TestFallbackTransaction_Rollback(t *testing.T) {
	storage := &logical.InmemStorage{}
	ctx := context.Background()

	storage.Put(ctx, &logical.StorageEntry{Key: "test/existing", Value: []byte("value")})

	txn := shimtx.NewInmemTransaction(storage)

	// Perform operations
	txn.Put(ctx, &logical.StorageEntry{Key: "test/new", Value: []byte("value")})
	txn.Delete(ctx, "test/existing")

	err := txn.Rollback(ctx)
	require.NoError(t, err)

	// validate
	result, err := storage.Get(ctx, "test/new")
	require.NoError(t, err)
	assert.Nil(t, result)

	result, err = storage.Get(ctx, "test/existing")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, []byte("value"), result.Value)
}

func TestFallbackTransaction_Commit(t *testing.T) {
	storage := &logical.InmemStorage{}
	ctx := context.Background()

	storage.Put(ctx, &logical.StorageEntry{Key: "test/existing", Value: []byte("value")})

	txn := shimtx.NewInmemTransaction(storage)

	// Perform operations
	txn.Put(ctx, &logical.StorageEntry{Key: "test/new", Value: []byte("value")})
	txn.Delete(ctx, "test/existing")

	err := txn.Commit(ctx)
	require.NoError(t, err)

	// validate
	result, err := storage.Get(ctx, "test/new")
	require.NoError(t, err)
	assert.EqualValues(t, []byte("value"), result.Value)

	result, err = storage.Get(ctx, "test/existing")
	require.NoError(t, err)
	assert.Nil(t, result)
}
