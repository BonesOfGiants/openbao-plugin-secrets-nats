package validate

import (
	"fmt"
	"slices"
	"strings"
)

type Key uint32

func ValidateFields(data map[string]any, valid []string) error {
	mapKeys := []string{}
	for key := range data {
		mapKeys = append(mapKeys, key)
	}

	invalidKeys := []string{}

	for _, key := range mapKeys {
		if !slices.Contains(valid, key) {
			invalidKeys = append(invalidKeys, key)
		}
	}

	if len(invalidKeys) > 0 {
		return fmt.Errorf(InvalidKeysError+": % #v", strings.Join(invalidKeys, ", "))
	}
	return nil
}
