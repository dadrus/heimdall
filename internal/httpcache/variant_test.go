// Copyright 2026 Dimitrij Drus <dadrus@gmx.de>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package httpcache

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVariantIsFreshAt(t *testing.T) {
	t.Parallel()

	const now = int64(100)

	for uc, tc := range map[string]struct {
		expiresAt int64
		expected  bool
	}{
		"should consider entry fresh before its expiration": {
			expiresAt: now + 1,
			expected:  true,
		},
		"should consider entry stale at its expiration": {
			expiresAt: now,
		},
		"should consider entry stale after its expiration": {
			expiresAt: now - 1,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// GIVEN
			entry := variant{ExpiresAt: tc.expiresAt}

			// WHEN
			actual := entry.isFreshAt(now)

			// THEN
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestVariantIsMoreRecentThan(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		entry    variant
		other    variant
		expected bool
	}{
		"should prefer the entry with the newer response date": {
			entry:    variant{ResponseDate: 20, StoredAt: 10},
			other:    variant{ResponseDate: 10, StoredAt: 30},
			expected: true,
		},
		"should reject the entry with the older response date": {
			entry: variant{ResponseDate: 10, StoredAt: 30},
			other: variant{ResponseDate: 20, StoredAt: 10},
		},
		"should use storage time as tie breaker": {
			entry:    variant{ResponseDate: 20, StoredAt: 30},
			other:    variant{ResponseDate: 20, StoredAt: 10},
			expected: true,
		},
		"should not consider identical entries more recent": {
			entry: variant{ResponseDate: 20, StoredAt: 30},
			other: variant{ResponseDate: 20, StoredAt: 30},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// WHEN
			actual := tc.entry.isMoreRecentThan(tc.other)

			// THEN
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestVariantGroupMostRecentMatch(t *testing.T) {
	t.Parallel()

	const now = int64(100)

	for uc, tc := range map[string]struct {
		group    variantGroup
		selector string
		expected variant
		found    bool
	}{
		"should not find a variant for an unknown selector": {
			group: variantGroup{Entries: []variant{
				{Selector: "known", ExpiresAt: now + 1},
			}},
			selector: "unknown",
		},
		"should ignore expired variants": {
			group: variantGroup{Entries: []variant{
				{Selector: "selected", ExpiresAt: now, ResponseDate: 30, StoredAt: 30},
			}},
			selector: "selected",
		},
		"should select the matching variant with the newest response date": {
			group: variantGroup{Entries: []variant{
				{Selector: "selected", ExpiresAt: now + 1, ResponseDate: 10, StoredAt: 30},
				{Selector: "other", ExpiresAt: now + 1, ResponseDate: 40, StoredAt: 40},
				{Selector: "selected", ExpiresAt: now + 1, ResponseDate: 20, StoredAt: 10},
			}},
			selector: "selected",
			expected: variant{Selector: "selected", ExpiresAt: now + 1, ResponseDate: 20, StoredAt: 10},
			found:    true,
		},
		"should use storage time when response dates are equal": {
			group: variantGroup{Entries: []variant{
				{Selector: "selected", ExpiresAt: now + 1, ResponseDate: 20, StoredAt: 10},
				{Selector: "selected", ExpiresAt: now + 1, ResponseDate: 20, StoredAt: 30},
			}},
			selector: "selected",
			expected: variant{Selector: "selected", ExpiresAt: now + 1, ResponseDate: 20, StoredAt: 30},
			found:    true,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// WHEN
			actual, found := tc.group.mostRecentMatch(tc.selector, now)

			// THEN
			assert.Equal(t, tc.found, found)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestVariantIndexMerge(t *testing.T) {
	t.Parallel()

	const now = int64(100)

	for uc, tc := range map[string]struct {
		index    variantIndex
		vary     []string
		stored   variant
		expected variantIndex
	}{
		"should add the first variant group": {
			index:  variantIndex{Version: variantIndexFormatVersion},
			vary:   []string{"Accept-Language"},
			stored: variant{Selector: "de", ExpiresAt: now + 10, StoredAt: 10},
			expected: variantIndex{
				Version: variantIndexFormatVersion,
				Groups: []variantGroup{
					{
						Vary: []string{"Accept-Language"},
						Entries: []variant{
							{Selector: "de", ExpiresAt: now + 10, StoredAt: 10},
						},
					},
				},
			},
		},
		"should replace the same selector and preserve other variants": {
			index: variantIndex{
				Version: variantIndexFormatVersion,
				Groups: []variantGroup{
					{
						Vary: []string{"Accept-Language"},
						Entries: []variant{
							{Selector: "de", ExpiresAt: now + 10, StoredAt: 10},
							{Selector: "en", ExpiresAt: now + 20, StoredAt: 20},
						},
					},
				},
			},
			vary:   []string{"Accept-Language"},
			stored: variant{Selector: "de", ExpiresAt: now + 30, StoredAt: 30},
			expected: variantIndex{
				Version: variantIndexFormatVersion,
				Groups: []variantGroup{
					{
						Vary: []string{"Accept-Language"},
						Entries: []variant{
							{Selector: "en", ExpiresAt: now + 20, StoredAt: 20},
							{Selector: "de", ExpiresAt: now + 30, StoredAt: 30},
						},
					},
				},
			},
		},
		"should remove expired entries and empty groups": {
			index: variantIndex{
				Version: variantIndexFormatVersion,
				Groups: []variantGroup{
					{
						Vary: []string{"Accept-Encoding"},
						Entries: []variant{
							{Selector: "gzip", ExpiresAt: now, StoredAt: 10},
						},
					},
					{
						Vary: []string{"Accept-Language"},
						Entries: []variant{
							{Selector: "en", ExpiresAt: now + 10, StoredAt: 20},
						},
					},
				},
			},
			vary:   []string{"X-Tenant"},
			stored: variant{Selector: "tenant-a", ExpiresAt: now + 20, StoredAt: 30},
			expected: variantIndex{
				Version: variantIndexFormatVersion,
				Groups: []variantGroup{
					{
						Vary: []string{"Accept-Language"},
						Entries: []variant{
							{Selector: "en", ExpiresAt: now + 10, StoredAt: 20},
						},
					},
					{
						Vary: []string{"X-Tenant"},
						Entries: []variant{
							{Selector: "tenant-a", ExpiresAt: now + 20, StoredAt: 30},
						},
					},
				},
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// WHEN
			tc.index.merge(tc.vary, tc.stored, now)

			// THEN
			assert.Equal(t, tc.expected, tc.index)
		})
	}
}

func TestVariantIndexMergeLimitsEntries(t *testing.T) {
	t.Parallel()

	// GIVEN
	entries := make([]variant, maxVariantEntriesPerTarget)
	for index := range entries {
		entries[index] = variant{
			Selector:  string(rune(index + 1)),
			ExpiresAt: 1000,
			StoredAt:  int64(index + 1),
		}
	}

	oldest := entries[0]
	index := variantIndex{
		Version: variantIndexFormatVersion,
		Groups: []variantGroup{
			{Vary: []string{"Accept-Language"}, Entries: entries},
		},
	}
	stored := variant{Selector: "new", ExpiresAt: 1000, StoredAt: maxVariantEntriesPerTarget + 1}

	// WHEN
	index.merge([]string{"Accept-Encoding"}, stored, 0)

	// THEN
	assert.Equal(t, maxVariantEntriesPerTarget, index.entryCount())
	assert.NotContains(t, index.Groups[0].Entries, oldest)
	assert.Contains(t, index.Groups[1].Entries, stored)
}

func TestVariantIndexLimitEntries(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		index    variantIndex
		limit    int
		expected variantIndex
	}{
		"should keep all entries within the limit": {
			index: variantIndex{
				Groups: []variantGroup{
					{Vary: []string{"Accept"}, Entries: []variant{{StoredAt: 10}}},
				},
			},
			limit: 1,
			expected: variantIndex{
				Groups: []variantGroup{
					{Vary: []string{"Accept"}, Entries: []variant{{StoredAt: 10}}},
				},
			},
		},
		"should remove the globally oldest entry": {
			index: variantIndex{
				Groups: []variantGroup{
					{
						Vary: []string{"Accept-Language"},
						Entries: []variant{
							{Selector: "oldest", StoredAt: 10},
							{Selector: "newest", StoredAt: 30},
						},
					},
					{
						Vary:    []string{"Accept-Encoding"},
						Entries: []variant{{Selector: "middle", StoredAt: 20}},
					},
				},
			},
			limit: 2,
			expected: variantIndex{
				Groups: []variantGroup{
					{
						Vary:    []string{"Accept-Language"},
						Entries: []variant{{Selector: "newest", StoredAt: 30}},
					},
					{
						Vary:    []string{"Accept-Encoding"},
						Entries: []variant{{Selector: "middle", StoredAt: 20}},
					},
				},
			},
		},
		"should remove groups left without entries": {
			index: variantIndex{
				Groups: []variantGroup{
					{
						Vary:    []string{"Accept-Language"},
						Entries: []variant{{Selector: "oldest", StoredAt: 10}},
					},
					{
						Vary:    []string{"Accept-Encoding"},
						Entries: []variant{{Selector: "newest", StoredAt: 20}},
					},
				},
			},
			limit: 1,
			expected: variantIndex{
				Groups: []variantGroup{
					{
						Vary:    []string{"Accept-Encoding"},
						Entries: []variant{{Selector: "newest", StoredAt: 20}},
					},
				},
			},
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// WHEN
			tc.index.limitEntries(tc.limit)

			// THEN
			assert.Equal(t, tc.expected, tc.index)
		})
	}
}

func TestVariantIndexOldestEntry(t *testing.T) {
	t.Parallel()

	for uc, tc := range map[string]struct {
		index              variantIndex
		expectedGroupIndex int
		expectedEntryIndex int
	}{
		"should return no indexes for an empty index": {
			expectedGroupIndex: -1,
			expectedEntryIndex: -1,
		},
		"should find the oldest entry across all groups": {
			index: variantIndex{
				Groups: []variantGroup{
					{Entries: []variant{{StoredAt: 30}, {StoredAt: 20}}},
					{Entries: []variant{{StoredAt: 10}, {StoredAt: 40}}},
				},
			},
			expectedGroupIndex: 1,
			expectedEntryIndex: 0,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// WHEN
			groupIndex, entryIndex := tc.index.oldestEntry()

			// THEN
			assert.Equal(t, tc.expectedGroupIndex, groupIndex)
			assert.Equal(t, tc.expectedEntryIndex, entryIndex)
		})
	}
}

func TestVariantIndexEntryCount(t *testing.T) {
	t.Parallel()

	// GIVEN
	index := variantIndex{
		Groups: []variantGroup{
			{Entries: make([]variant, 2)},
			{Entries: make([]variant, 3)},
		},
	}

	// WHEN
	actual := index.entryCount()

	// THEN
	assert.Equal(t, 5, actual)
}

func TestVariantIndexTTL(t *testing.T) {
	t.Parallel()

	// GIVEN
	now := time.Unix(100, 0)
	index := variantIndex{
		Groups: []variantGroup{
			{
				Entries: []variant{
					{ExpiresAt: now.Add(10 * time.Second).UnixNano()},
					{ExpiresAt: now.Add(30 * time.Second).UnixNano()},
				},
			},
			{
				Entries: []variant{
					{ExpiresAt: now.Add(20 * time.Second).UnixNano()},
				},
			},
		},
	}

	// WHEN
	actual := index.ttl(now)

	// THEN
	assert.Equal(t, 30*time.Second, actual)
}

func TestDecodeVariantIndex(t *testing.T) {
	t.Parallel()

	marshal := func(value any) []byte {
		data, err := json.Marshal(value)
		require.NoError(t, err)

		return data
	}

	valid := variantIndex{
		Version: variantIndexFormatVersion,
		Groups: []variantGroup{
			{
				Vary: []string{"Accept-Language"},
				Entries: []variant{
					{Selector: "de", ExpiresAt: 10, ResponseDate: 5, StoredAt: 5},
				},
			},
		},
	}

	tooManyEntries := variantIndex{
		Version: variantIndexFormatVersion,
		Groups: []variantGroup{
			{Entries: make([]variant, maxVariantEntriesPerTarget+1)},
		},
	}

	for uc, tc := range map[string]struct {
		data          []byte
		expected      variantIndex
		expectedError error
		errorExpected bool
	}{
		"should decode a valid index": {
			data:     marshal(valid),
			expected: valid,
		},
		"should reject empty data": {
			expectedError: ErrNoCacheEntry,
			errorExpected: true,
		},
		"should reject an oversized index": {
			data:          make([]byte, maxVariantIndexSize+1),
			expectedError: ErrNoCacheEntry,
			errorExpected: true,
		},
		"should reject malformed json": {
			data:          []byte("{"),
			errorExpected: true,
		},
		"should reject an unsupported format version": {
			data: marshal(variantIndex{
				Version: variantIndexFormatVersion + 1,
			}),
			expectedError: ErrNoCacheEntry,
			errorExpected: true,
		},
		"should reject an index exceeding the entry limit": {
			data:          marshal(tooManyEntries),
			expectedError: ErrNoCacheEntry,
			errorExpected: true,
		},
	} {
		t.Run(uc, func(t *testing.T) {
			// WHEN
			actual, err := decodeVariantIndex(tc.data)

			// THEN
			if tc.errorExpected {
				require.Error(t, err)
				assert.Equal(t, variantIndex{}, actual)
				if tc.expectedError != nil {
					assert.ErrorIs(t, err, tc.expectedError)
				}

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.expected, actual)
		})
	}
}
