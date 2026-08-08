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
	"slices"
	"time"
)

type variant struct {
	Selector     string `json:"selector"`
	ResponseID   string `json:"response_id"`
	ExpiresAt    int64  `json:"expires_at"`
	ResponseDate int64  `json:"response_date"`
	StoredAt     int64  `json:"stored_at"`
}

func (entry variant) isFreshAt(now int64) bool {
	return entry.ExpiresAt > now
}

func (entry variant) isMoreRecentThan(other variant) bool {
	if entry.ResponseDate != other.ResponseDate {
		return entry.ResponseDate > other.ResponseDate
	}

	return entry.StoredAt > other.StoredAt
}

type variantGroup struct {
	Vary    []string  `json:"vary,omitempty"`
	Entries []variant `json:"entries"`
}

func (group variantGroup) mostRecentMatch(selector string, now int64) (variant, bool) {
	var match variant

	found := false

	for _, entry := range group.Entries {
		if !entry.isFreshAt(now) || entry.Selector != selector {
			continue
		}

		if !found || entry.isMoreRecentThan(match) {
			match = entry
			found = true
		}
	}

	return match, found
}

type variantIndex struct {
	Version int            `json:"version"`
	Groups  []variantGroup `json:"groups"`
}

func (index *variantIndex) merge(storedVary []string, stored variant, now int64) {
	groups := index.Groups[:0]
	storedAppended := false

	for _, group := range index.Groups {
		sameGroup := slices.Equal(group.Vary, storedVary)
		entries := group.Entries[:0]

		for _, entry := range group.Entries {
			if !entry.isFreshAt(now) || (sameGroup && entry.Selector == stored.Selector) {
				continue
			}

			entries = append(entries, entry)
		}

		if sameGroup && !storedAppended {
			entries = append(entries, stored)
			storedAppended = true
		}

		if len(entries) == 0 {
			continue
		}

		group.Entries = entries
		groups = append(groups, group)
	}

	if !storedAppended {
		groups = append(groups, variantGroup{
			Vary:    storedVary,
			Entries: []variant{stored},
		})
	}

	index.Groups = groups
	index.limitEntries(maxVariantEntriesPerTarget)
}

func (index *variantIndex) limitEntries(limit int) {
	count := index.entryCount()
	for count > limit {
		groupIndex, entryIndex := index.oldestEntry()
		if groupIndex < 0 {
			break
		}

		index.Groups[groupIndex].Entries = slices.Delete(
			index.Groups[groupIndex].Entries,
			entryIndex,
			entryIndex+1,
		)
		count--
	}

	groups := index.Groups[:0]
	for _, group := range index.Groups {
		if len(group.Entries) != 0 {
			groups = append(groups, group)
		}
	}

	index.Groups = groups
}

func (index *variantIndex) oldestEntry() (int, int) {
	oldestGroup := -1
	oldestEntry := -1

	for groupIndex := range index.Groups {
		for entryIndex := range index.Groups[groupIndex].Entries {
			entry := index.Groups[groupIndex].Entries[entryIndex]
			if oldestGroup < 0 ||
				entry.StoredAt < index.Groups[oldestGroup].Entries[oldestEntry].StoredAt {
				oldestGroup = groupIndex
				oldestEntry = entryIndex
			}
		}
	}

	return oldestGroup, oldestEntry
}

func (index *variantIndex) entryCount() int {
	count := 0
	for _, group := range index.Groups {
		count += len(group.Entries)
	}

	return count
}

func (index *variantIndex) ttl(now time.Time) time.Duration {
	var latestExpiration int64

	for _, group := range index.Groups {
		for _, entry := range group.Entries {
			if entry.ExpiresAt > latestExpiration {
				latestExpiration = entry.ExpiresAt
			}
		}
	}

	return time.Unix(0, latestExpiration).Sub(now)
}

func decodeVariantIndex(data []byte) (variantIndex, error) {
	if len(data) == 0 || len(data) > maxVariantIndexSize {
		return variantIndex{}, ErrNoCacheEntry
	}

	var index variantIndex
	if err := json.Unmarshal(data, &index); err != nil {
		return variantIndex{}, err
	}

	if index.Version != variantIndexFormatVersion ||
		index.entryCount() > maxVariantEntriesPerTarget {
		return variantIndex{}, ErrNoCacheEntry
	}

	return index, nil
}
