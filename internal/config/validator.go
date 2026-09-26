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

package config

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/knadh/koanf/maps"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
	"gopkg.in/yaml.v3"

	"github.com/dadrus/heimdall/internal/pipeline"
	"github.com/dadrus/heimdall/internal/x/errorchain"
	"github.com/dadrus/heimdall/internal/x/stringx"
	"github.com/dadrus/heimdall/schema"
)

func ValidateConfigSchema(src io.Reader) error {
	var conf map[string]any

	err := yaml.NewDecoder(src).Decode(&conf)
	if err != nil {
		return errorchain.NewWithMessage(pipeline.ErrConfiguration,
			"failed to parse config").CausedBy(err)
	}

	compiledSchema, err := compileSchema("config.schema.json", stringx.ToString(schema.ConfigSchema))
	if err != nil {
		return errorchain.NewWithMessage(pipeline.ErrConfiguration,
			"failed to compile JSON schema").CausedBy(err)
	}

	maps.IntfaceKeysToStrings(conf)

	err = compiledSchema.Validate(conf)
	if err != nil {
		if ve, ok := errors.AsType[*jsonschema.ValidationError](err); ok {
			return errorchain.NewWithMessage(pipeline.ErrConfiguration, formatValidationError(ve))
		}

		return errorchain.New(pipeline.ErrConfiguration).CausedBy(err)
	}

	return nil
}

func compileSchema(url, schemaContent string) (*jsonschema.Schema, error) {
	configSchema, err := jsonschema.UnmarshalJSON(strings.NewReader(schemaContent))
	if err != nil {
		return nil, err
	}

	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource(url, configSchema); err != nil {
		return nil, err
	}

	return compiler.Compile(url)
}

func formatValidationError(err *jsonschema.ValidationError) string {
	p := message.NewPrinter(language.English)

	var lines []string
	collectValidationLeaves(err, p, &lines)

	if len(lines) == 0 {
		return "configuration is invalid"
	}

	return "failed to validate configuration against schema:\n" + strings.Join(lines, "\n")
}

func collectValidationLeaves(
	err *jsonschema.ValidationError,
	printer *message.Printer,
	lines *[]string,
) {
	if err == nil {
		return
	}

	if len(err.Causes) > 0 {
		for _, cause := range err.Causes {
			collectValidationLeaves(cause, printer, lines)
		}

		return
	}

	if err.ErrorKind == nil {
		return
	}

	path := formatInstanceLocation(err.InstanceLocation)
	msg := err.ErrorKind.LocalizedString(printer)

	*lines = append(*lines, fmt.Sprintf("- %s: %s", path, msg))
}

func formatInstanceLocation(loc []string) string {
	if len(loc) == 0 {
		return "$"
	}

	var builder strings.Builder

	for _, part := range loc {
		if _, err := strconv.Atoi(part); err == nil {
			builder.WriteString("[")
			builder.WriteString(part)
			builder.WriteString("]")

			continue
		}

		if builder.Len() > 0 {
			builder.WriteString(".")
		}

		builder.WriteString(part)
	}

	return builder.String()
}
