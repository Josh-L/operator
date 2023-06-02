// Copyright (c) 2023 Tigera, Inc. All rights reserved.

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
package render

import (
	operatorv1 "github.com/tigera/operator/api/v1"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ Component = &tenantIsolater{}

func NewTenantIsolater(c Component, ns string) Component {
	return &tenantIsolater{
		c:  c,
		ns: ns,
	}
}

// tenantIsolater is a helper implementation of the Component interface to abstract away
// the handling of tenant isolation. It modifies the namespace of any created resources if tenancy is enabled.
type tenantIsolater struct {
	tenant string
	c      Component
	ns     string
}

func (t *tenantIsolater) ResolveImages(is *operatorv1.ImageSet) error {
	return t.c.ResolveImages(is)
}

func (t *tenantIsolater) Objects() (objsToCreate []client.Object, objsToDelete []client.Object) {
	if t.ns == "" {
		return t.c.Objects()
	}

	// Modify any namespaced objects to use the tenant's namespace.
	c, d := t.c.Objects()
	for _, o := range c {
		if o.GetNamespace() != "" {
			o.SetNamespace(t.ns)
		}
	}
	for _, o := range d {
		if o.GetNamespace() != "" {
			o.SetNamespace(t.ns)
		}
	}
	return c, d
}

func (t *tenantIsolater) Ready() bool {
	return t.c.Ready()
}

func (t *tenantIsolater) SupportedOSType() rmeta.OSType {
	return t.c.SupportedOSType()
}
