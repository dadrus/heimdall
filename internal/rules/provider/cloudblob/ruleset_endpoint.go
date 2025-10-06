// Copyright 2022 Dimitrij Drus <dadrus@gmx.de>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package cloudblob

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"

	"github.com/dadrus/heimdall/internal/rules/api/common"
	"gocloud.dev/blob"
	_ "gocloud.dev/blob/azureblob" // to support azure blobs
	_ "gocloud.dev/blob/gcsblob"   // to support gc storage blobs
	_ "gocloud.dev/blob/s3blob"    // to support aws s3 blobs
	"gocloud.dev/gcerrors"

	"github.com/dadrus/heimdall/internal/app"
	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/api/v1beta1"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type ruleSetEndpoint struct {
	URL    *url.URL `mapstructure:"url"`
	Prefix string   `mapstructure:"prefix"`
}

func (e *ruleSetEndpoint) ID() string {
	return fmt.Sprintf("%s/%s", e.URL, e.Prefix)
}

func (e *ruleSetEndpoint) FetchRuleSets(
	ctx context.Context,
	app app.Context,
) ([]*v1beta1.RuleSet, error) {
	bucket, err := blob.OpenBucket(ctx, e.URL.String())
	if err != nil {
		return nil, errorchain.NewWithMessage(heimdall.ErrInternal, "failed to open bucket").
			CausedBy(err)
	}

	defer bucket.Close()

	if len(e.URL.Path) != 0 {
		return e.readSingleBlob(ctx, bucket, app)
	}

	return e.readAllBlobs(ctx, bucket, app)
}

func (e *ruleSetEndpoint) readAllBlobs(
	ctx context.Context,
	bucket *blob.Bucket,
	app app.Context,
) ([]*v1beta1.RuleSet, error) {
	var ruleSets []*v1beta1.RuleSet

	it := bucket.List(&blob.ListOptions{Prefix: e.Prefix})

	for {
		obj, err := it.Next(ctx)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}

			return nil, mapError(err, "failed iterate blobs")
		}

		ruleSet, err := e.readRuleSet(ctx, bucket, obj.Key, app)
		if err != nil {
			if errors.Is(err, io.EOF) {
				continue
			}

			return nil, err
		}

		ruleSets = append(ruleSets, ruleSet)
	}

	return ruleSets, nil
}

func (e *ruleSetEndpoint) readSingleBlob(
	ctx context.Context,
	bucket *blob.Bucket,
	app app.Context,
) ([]*v1beta1.RuleSet, error) {
	ruleSet, err := e.readRuleSet(ctx, bucket, e.URL.Path, app)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return []*v1beta1.RuleSet{}, nil
		}

		return nil, err
	}

	return []*v1beta1.RuleSet{ruleSet}, nil
}

func (e *ruleSetEndpoint) readRuleSet(
	ctx context.Context,
	bucket *blob.Bucket,
	key string,
	app app.Context,
) (
	*v1beta1.RuleSet, error,
) {
	attrs, err := bucket.Attributes(ctx, key)
	if err != nil {
		return nil, mapError(err, "failed to get blob attributes")
	}

	reader, err := bucket.NewReader(ctx, key, nil)
	if err != nil {
		return nil, mapError(err, "failed reading blob contents")
	}

	defer reader.Close()

	dec := common.NewDecoder[v1beta1.RuleSet](
		common.WithSourceContentType(attrs.ContentType),
		common.WithValidator(common.ValidatorFunc(app.Validator().ValidateStruct)),
		common.WithErrorOnUnused(true),
	)

	contents, err := dec.Decode(reader)
	if err != nil {
		return nil, errorchain.
			NewWithMessage(heimdall.ErrInternal, "failed to decode received rule set").
			CausedBy(err)
	}

	contents.Hash = attrs.MD5
	contents.Source = fmt.Sprintf("%s@%s", key, e.ID())
	contents.ModTime = attrs.ModTime

	return &contents, nil
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
