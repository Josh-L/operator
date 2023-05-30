package render

import (
	operatorv1 "github.com/tigera/operator/api/v1"
	rmeta "github.com/tigera/operator/pkg/render/common/meta"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ Component = &tenantIsolater{}

func NewTenantIsolater(c Component) Component {
	return &tenantIsolater{
		c: c,
	}
}

// tenantIsolater is a helper implementation of the Component interface to abstract away
// the handling of tenant isolation. It modifies the namespace of any created resources if tenancy is enabled.
type tenantIsolater struct {
	tenant string
	c      Component
}

func (t *tenantIsolater) ResolveImages(is *operatorv1.ImageSet) error {
	return t.c.ResolveImages(is)
}

func (t *tenantIsolater) Objects() (objsToCreate []client.Object, objsToDelete []client.Object) {
	if t.tenant == "" {
		return t.c.Objects()
	}

	// TODO: Call objects, and then modify them to update their namespace as needed.
	c, d := t.c.Objects()
	return c, d
}

func (t *tenantIsolater) Ready() bool {
	return t.c.Ready()
}

func (t *tenantIsolater) SupportedOSType() rmeta.OSType {
	return t.c.SupportedOSType()
}
