// Copyright 2025 Dimitrij Drus <dadrus@gmx.de>
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

package oauth2

import (
	"context"
	"os"

	"github.com/dadrus/heimdall/internal/heimdall"
	"github.com/dadrus/heimdall/internal/rules/mechanisms/template"
	"github.com/dadrus/heimdall/internal/x/errorchain"
)

type FileMetadataResolver struct {
	FilePath string `mapstructure:"path" validate:"required"`
}

func (f *FileMetadataResolver) Get(ctx context.Context, args map[string]any) (ServerMetadata, error) {
	// Render template if needed
	filePath, err := f.renderPath(args)
	if err != nil {
		return ServerMetadata{}, err
	}

	// Validate file exists and is readable
	fInfo, err := os.Stat(filePath)
	if err != nil {
		return ServerMetadata{}, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"JWKS file '%s' not found or not accessible", filePath).CausedBy(err)
	}

	if fInfo.IsDir() {
		return ServerMetadata{}, errorchain.NewWithMessagef(heimdall.ErrConfiguration,
			"'%s' is a directory, not a file", filePath)
	}

	// Return metadata with file path - the actual file reading will be handled by the JWT authenticator
	return ServerMetadata{
		JWKSFilePath: filePath,
	}, nil
}

func (f *FileMetadataResolver) renderPath(args map[string]any) (string, error) {
	if args == nil || len(args) == 0 {
		return f.FilePath, nil
	}

	tpl, err := template.New(f.FilePath)
	if err != nil {
		return "", errorchain.NewWithMessage(heimdall.ErrInternal, "failed to create template for JWKS file path").
			CausedBy(err)
	}

	return tpl.Render(args)
}
