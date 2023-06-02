// Copyright (c) 2023 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package manager

import (
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"k8s.io/apimachinery/pkg/types"
)

type Request struct {
	// The name and namespace of the object that triggered this request.
	types.NamespacedName

	instance     *operatorv1.Manager
	variant      operatorv1.ProductVariant
	installation *operatorv1.InstallationSpec
	license      v3.LicenseKey
}

// InstallNamespace returns the namespace that components will be installed into.
// for single-tenant clusters, this is tigera-manager. For multi-tenancy, this
// will be the tenant's namespace.
func (r *Request) InstallNamespace() string {
	// TODO: This should sometimes return tigera-manager, and return the
	// tenant's namespace in multi-tenant clusters.
	return r.NamespacedName.Namespace
}

// TruthNamespace returns the namespace to use as the source of truth for storing data.
// For single-tenant installs, this is the tigera-operator namespace.
// For multi-tenant installs, this is tenant's namespace.
func (r *Request) TruthNamespace() string {
	// TODO: This should sometimes return tigera-operator, and return the
	// tenant's namespace in multi-tenant clusters.
	return r.NamespacedName.Namespace
}
