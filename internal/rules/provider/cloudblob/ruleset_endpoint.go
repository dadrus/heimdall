package cloudblob

import (
	"context"
	"errors"
	"fmt"
	"io"

	"gocloud.dev/blob"
	_ "gocloud.dev/blob/azureblob" // to support azure blobs
	_ "gocloud.dev/blob/gcsblob"   // to support gc storage blobs
	_ "gocloud.dev/blob/s3blob"    // to support aws s3 blobs

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/provider/pathprefix"
	"github.com/dadrus/heimdall/internal/rules/provider/rulesetparser"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type ruleSetEndpoint struct {
	URL             string                `mapstructure:"url"`
	Prefix          string                `mapstructure:"prefix"`
	RulesPathPrefix pathprefix.PathPrefix `mapstructure:"rules_path_prefix"`
}

func (e *ruleSetEndpoint) ID() string {
	return fmt.Sprintf("%s/%s", e.URL, e.Prefix)
}

func (e *ruleSetEndpoint) FetchRuleSets(ctx context.Context) ([]RuleSet, error) {
	bucket, err := blob.OpenBucket(ctx, e.URL)
	if err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrInternal, "failed to open bucket").
			CausedBy(err)
	}

	defer bucket.Close()

	var ruleSets []RuleSet

	it := bucket.List(&blob.ListOptions{Prefix: e.Prefix})

	for {
		obj, err := it.Next(ctx)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}

			return nil, errorchain.NewWithMessage(heimdall.ErrInternal, "failed iterate blobs").
				CausedBy(err)
		}

		attrs, err := bucket.Attributes(ctx, obj.Key)
		if err != nil {
			return nil, errorchain.NewWithMessage(heimdall.ErrInternal, "failed to get blob attributes").
				CausedBy(err)
		}

		reader, err := bucket.NewReader(ctx, obj.Key, nil)
		if err != nil {
			return nil, errorchain.NewWithMessage(heimdall.ErrInternal, "failed reading blob contents").
				CausedBy(err)
		}

		contents, err := rulesetparser.ParseRules(attrs.ContentType, reader)
		if err != nil {
			return nil, errorchain.NewWithMessage(heimdall.ErrInternal, "failed to decode received rule set").
				CausedBy(err)
		}

		if err = e.RulesPathPrefix.Verify(contents); err != nil {
			return nil, err
		}

		ruleSets = append(ruleSets, RuleSet{
			Rules:   contents,
			Hash:    obj.MD5,
			Key:     fmt.Sprintf("%s@%s", obj.Key, e.ID()),
			ModTime: obj.ModTime,
		})
	}

	return ruleSets, nil
}
