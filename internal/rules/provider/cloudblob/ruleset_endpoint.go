package cloudblob

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"

	"gocloud.dev/blob"
	_ "gocloud.dev/blob/azureblob" // to support azure blobs
	_ "gocloud.dev/blob/gcsblob"   // to support gc storage blobs
	_ "gocloud.dev/blob/s3blob"    // to support aws s3 blobs
	"gocloud.dev/gcerrors"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/provider/pathprefix"
	"github.com/dadrus/heimdall/internal/rules/provider/rulesetparser"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

var errEmptyRuleSet = errors.New("empty rule set")

type ruleSetEndpoint struct {
	URL             *url.URL              `mapstructure:"url"`
	Prefix          string                `mapstructure:"prefix"`
	RulesPathPrefix pathprefix.PathPrefix `mapstructure:"rule_path_match_prefix"`
}

func (e *ruleSetEndpoint) ID() string {
	return fmt.Sprintf("%s/%s", e.URL, e.Prefix)
}

func (e *ruleSetEndpoint) FetchRuleSets(ctx context.Context) ([]RuleSet, error) {
	bucket, err := blob.OpenBucket(ctx, e.URL.String())
	if err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrInternal, "failed to open bucket").
			CausedBy(err)
	}

	defer bucket.Close()

	if len(e.URL.Path) != 0 {
		return e.readSingleBlob(ctx, bucket)
	}

	return e.readAllBlobs(ctx, bucket)
}

func (e *ruleSetEndpoint) readAllBlobs(ctx context.Context, bucket *blob.Bucket) ([]RuleSet, error) {
	var ruleSets []RuleSet

	it := bucket.List(&blob.ListOptions{Prefix: e.Prefix})

	for {
		obj, err := it.Next(ctx)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}

			return nil, mapError(err, "failed iterate blobs")
		}

		ruleSet, err := e.readRuleSet(ctx, bucket, obj.Key)
		if err != nil {
			if errors.Is(err, errEmptyRuleSet) {
				continue
			}

			return nil, err
		}

		ruleSets = append(ruleSets, ruleSet)
	}

	return ruleSets, nil
}

func (e *ruleSetEndpoint) readSingleBlob(ctx context.Context, bucket *blob.Bucket) ([]RuleSet, error) {
	ruleSet, err := e.readRuleSet(ctx, bucket, e.URL.Path)
	if err != nil {
		if errors.Is(err, errEmptyRuleSet) {
			return []RuleSet{}, nil
		}

		return nil, err
	}

	return []RuleSet{ruleSet}, nil
}

func (e *ruleSetEndpoint) readRuleSet(ctx context.Context, bucket *blob.Bucket, key string) (RuleSet, error) {
	attrs, err := bucket.Attributes(ctx, key)
	if err != nil {
		return RuleSet{}, mapError(err, "failed to get blob attributes")
	}

	reader, err := bucket.NewReader(ctx, key, nil)
	if err != nil {
		return RuleSet{}, mapError(err, "failed reading blob contents")
	}

	defer reader.Close()

	contents, err := rulesetparser.ParseRules(attrs.ContentType, reader)
	if err != nil {
		return RuleSet{}, errorchain.NewWithMessage(heimdall.ErrInternal, "failed to decode received rule set").
			CausedBy(err)
	}

	if len(contents) == 0 {
		return RuleSet{}, errEmptyRuleSet
	}

	if err = e.RulesPathPrefix.Verify(contents); err != nil {
		return RuleSet{}, err
	}

	return RuleSet{
		Rules:   contents,
		Hash:    attrs.MD5,
		Key:     fmt.Sprintf("%s@%s", key, e.ID()),
		ModTime: attrs.ModTime,
	}, nil
}

func mapError(err error, message string) error {
	// unfortunately some cloud provider SDKs don't implement error Is and/or As functions,
	// so it is impossible to properly check for the actual underlying error.
	switch gcerrors.Code(err) {
	case gcerrors.Unknown:
		fallthrough
	case gcerrors.Canceled:
		return errorchain.NewWithMessage(heimdall.ErrCommunication, message).CausedBy(err)
	case gcerrors.DeadlineExceeded:
		return errorchain.NewWithMessage(heimdall.ErrCommunicationTimeout, message).CausedBy(err)
	default:
		return errorchain.NewWithMessage(heimdall.ErrInternal, message).CausedBy(err)
	}
}
