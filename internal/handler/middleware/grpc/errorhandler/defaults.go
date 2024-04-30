// Copyright 2023 Dimitrij Drus <dadrus@gmx.de>
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

package errorhandler

import (
	"net/http"

	"google.golang.org/grpc/codes"
)

var defaultOptions = opts{ //nolint:gochecknoglobals
	authenticationError: responseWith(codes.Unauthenticated, http.StatusUnauthorized),
	authorizationError:  responseWith(codes.PermissionDenied, http.StatusForbidden),
	communicationError:  responseWith(codes.DeadlineExceeded, http.StatusBadGateway),
	preconditionError:   responseWith(codes.InvalidArgument, http.StatusBadRequest),
	noRuleError:         responseWith(codes.NotFound, http.StatusNotFound),
	internalError:       responseWith(codes.Internal, http.StatusInternalServerError),
}
