package indextree

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReverseDomain(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		domain   string
		expected string
	}{
		{"example.com", "com.example"},
		{"subdomain.example.com", "com.example.subdomain"},
		{"www.github.com", "com.github.www"},
		{"test", "test"},
		{"", ""},
	} {
		result := reverseDomain(test.domain)
		assert.Equal(t, test.expected, result)
	}
}

func TestDomainTree(t *testing.T) {
	t.Parallel()

	tree := &domainNode[string]{}

	for _, domain := range []string{
		"example.com",
		"*.example.com",
		"subdomain.example.com",
		"static.example.com",
		"www.github.com",
		"test",
		"foo.net",
		"bar.net",
		"baz.net",
	} {
		tree.add(domain)
	}

	for _, tc := range []struct {
		domain   string
		expected string
	}{
		{"example.com", "example.com"},
		{"subdomain.example.com", "subdomain.example.com"},
		{"static.example.com", "static.example.com"},
		{"test.example.com", "*.example.com"},
		{"bar.example.com", "*.example.com"},
		{"foo.bar.example.com", "*.example.com"},
		{"www.github.com", "www.github.com"},
		{"test", "test"},
		{"foo.net", "foo.net"},
		{"bar.net", "bar.net"},
		{"baz.net", "baz.net"},
		{"com", ""},
		{"example", ""},
		{"example.com.", ""},
		{"example.com..", ""},
		{"example.com..subdomain", ""},
		{"example.com..subdomain.", ""},
		{"example.com..subdomain..", ""},
		{"bar.foo.net", ""},
		{"foo.bar.net", ""},
		{"baz.bar.net", ""},
		{"test.example.com.", ""},
		{"com.example", ""},
		{"com.example.subdomain", ""},
		{"com.github.www", ""},
	} {
		t.Run(tc.domain, func(t *testing.T) {
			res := tree.find(tc.domain)

			if tc.expected != "" {
				require.NotNil(t, res)
				assert.Equal(t, tc.expected, res.fullDomain)
			} else if tc.expected == "" {
				assert.Nil(t, res)
			}
		})
	}

	// test global wildcard
	tree.add("*")

	for _, tc := range []struct {
		domain   string
		expected string
	}{
		{"com", "*"},
		{"example", "*"},
		{"example.com.", "*"},
		{"example.com..", "*"},
		{"example.com..subdomain", "*"},
		{"example.com..subdomain.", "*"},
		{"example.com..subdomain..", "*"},
		{"bar.foo.net", "*"},
		{"foo.bar.net", "*"},
		{"baz.bar.net", "*"},
		{"test.example.com.", "*"},
		{"com.example", "*"},
		{"com.example.subdomain", "*"},
		{"com.github.www", "*"},
		// ensure global wildcard doesn't override existing domains
		{"example.com", "example.com"},
		{"subdomain.example.com", "subdomain.example.com"},
		{"static.example.com", "static.example.com"},
		{"test.example.com", "*.example.com"},
		{"bar.example.com", "*.example.com"},
		{"foo.bar.example.com", "*.example.com"},
		{"www.github.com", "www.github.com"},
		{"test", "test"},
		{"foo.net", "foo.net"},
		{"bar.net", "bar.net"},
		{"baz.net", "baz.net"},
	} {
		t.Run(tc.domain, func(t *testing.T) {
			res := tree.find(tc.domain)

			if tc.expected != "" {
				require.NotNil(t, res)
				assert.Equal(t, tc.expected, res.fullDomain)
			} else if tc.expected == "" {
				assert.Nil(t, res)
			}
		})
	}
}

func TestDeleteDomain(t *testing.T) {
	t.Parallel()

	tree := &domainNode[string]{}

	for _, domain := range []string{
		"example.com",
		"*.example.com",
		"subdomain.example.com",
		"static.example.com",
		"spoof.example.com",
		"different.example.com",
		"www.github.com",
		"test",
		"foo.net",
		"bar.net",
		"baz.net",
	} {
		tree.add(domain)
	}

	for _, tc := range []struct {
		domain     string
		expRemoved bool
		expected   string
	}{
		{"www.github.com", true, ""},
		{"example.com", true, ""},
		{"subdomain.example.com", true, "*.example.com"},
		{"test.example.com", false, "*.example.com"},
		{"bar.example.com", false, "*.example.com"},
		{"foo.bar.example.com", false, "*.example.com"},
		{"*.example.com", true, ""},
		{"subdomain.example.com", false, ""},
		{"spoof.example.com", true, ""},
		{"test.example.com", false, ""},
		{"bar.example.com", false, ""},
		{"foo.bar.example.com", false, ""},
		{"test", true, ""},
		{"foo.net", true, ""},
		{"bar.net", true, ""},
		{"baz.net", true, ""},
		{"com", false, ""},
		{"example", false, ""},
		{"example.com.", false, ""},
		{"example.com..", false, ""},
		{"example.com..subdomain", false, ""},
		{"example.com..subdomain.", false, ""},
		{"example.com..subdomain..", false, ""},
		{"bar.foo.net", false, ""},
		{"foo.bar.net", false, ""},
		{"baz.bar.net", false, ""},
		{"test.example.com.", false, ""},
		{"com.example", false, ""},
		{"com.example.subdomain", false, ""},
		{"com.github.www", false, ""},
		{"test", false, ""},
	} {
		result := tree.delete(tc.domain)
		require.Equalf(t, tc.expRemoved, result, "Delete(%s) returned %v, expected %v", tc.domain, result, tc.expRemoved)

		res := tree.find(tc.domain)

		if tc.expected != "" {
			require.NotNil(t, res)
			assert.Equal(t, tc.expected, res.fullDomain)
		} else if tc.expected == "" {
			assert.Nil(t, res)
		}
	}
}
