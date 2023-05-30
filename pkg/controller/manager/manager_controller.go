// Copyright (c) 2020-2023 Tigera, Inc. All rights reserved.

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
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/go-logr/logr"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/certificatemanager"
	"github.com/tigera/operator/pkg/controller/compliance"
	"github.com/tigera/operator/pkg/controller/options"
	"github.com/tigera/operator/pkg/controller/status"
	"github.com/tigera/operator/pkg/controller/utils"
	"github.com/tigera/operator/pkg/controller/utils/imageset"
	"github.com/tigera/operator/pkg/dns"
	"github.com/tigera/operator/pkg/render"
	rcertificatemanagement "github.com/tigera/operator/pkg/render/certificatemanagement"
	tigerakvc "github.com/tigera/operator/pkg/render/common/authentication/tigera/key_validator_config"
	relasticsearch "github.com/tigera/operator/pkg/render/common/elasticsearch"
	"github.com/tigera/operator/pkg/render/common/networkpolicy"
	"github.com/tigera/operator/pkg/render/monitor"
	"github.com/tigera/operator/pkg/tls/certificatemanagement"
)

const ResourceName = "manager"

var log = logf.Log.WithName("controller_manager")

// Add creates a new Manager Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager, opts options.AddOptions) error {
	if !opts.EnterpriseCRDExists {
		// No need to start this controller.
		return nil
	}

	licenseAPIReady := &utils.ReadyFlag{}
	tierWatchReady := &utils.ReadyFlag{}

	// create the reconciler
	reconciler := newReconciler(mgr, opts, licenseAPIReady, tierWatchReady)

	// Create a new controller
	controller, err := controller.New("cmanager-controller", mgr, controller.Options{Reconciler: reconcile.Reconciler(reconciler)})
	if err != nil {
		return fmt.Errorf("failed to create manager-controller: %w", err)
	}

	k8sClient, err := kubernetes.NewForConfig(mgr.GetConfig())
	if err != nil {
		log.Error(err, "Failed to establish a connection to k8s")
		return err
	}

	err = utils.AddSecretsWatch(controller, render.VoltronLinseedTLS, render.ManagerNamespace)
	if err != nil {
		return err
	}

	go utils.WaitToAddLicenseKeyWatch(controller, k8sClient, log, licenseAPIReady)
	go utils.WaitToAddTierWatch(networkpolicy.TigeraComponentTierName, controller, k8sClient, log, tierWatchReady)
	go utils.WaitToAddNetworkPolicyWatches(controller, k8sClient, log, []types.NamespacedName{
		{Name: render.ManagerPolicyName, Namespace: render.ManagerNamespace},
		{Name: networkpolicy.TigeraComponentDefaultDenyPolicyName, Namespace: render.ManagerNamespace},
	})

	return add(mgr, controller)
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager, opts options.AddOptions, licenseAPIReady *utils.ReadyFlag, tierWatchReady *utils.ReadyFlag) reconcile.Reconciler {
	c := &ReconcileManager{
		client:          mgr.GetClient(),
		scheme:          mgr.GetScheme(),
		provider:        opts.DetectedProvider,
		status:          status.New(mgr.GetClient(), "manager", opts.KubernetesVersion),
		clusterDomain:   opts.ClusterDomain,
		licenseAPIReady: licenseAPIReady,
		tierWatchReady:  tierWatchReady,
		usePSP:          opts.UsePSP,
	}
	c.status.Run(opts.ShutdownContext)
	return c
}

// add adds watches for resources that are available at startup
func add(mgr manager.Manager, c controller.Controller) error {
	var err error

	// Watch for changes to primary resource Manager
	err = c.Watch(&source.Kind{Type: &operatorv1.Manager{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("manager-controller failed to watch primary resource: %w", err)
	}

	err = utils.AddAPIServerWatch(c)
	if err != nil {
		return fmt.Errorf("manager-controller failed to watch APIServer resource: %w", err)
	}

	err = utils.AddComplianceWatch(c)
	if err != nil {
		return fmt.Errorf("manager-controller failed to watch compliance resource: %w", err)
	}

	// Watch the given secrets in each both the manager and operator namespaces
	// TODO: This won't be operator namespace in multi-tenant.
	for _, namespace := range []string{common.OperatorNamespace(), render.ManagerNamespace} {
		for _, secretName := range []string{
			render.ManagerTLSSecretName, relasticsearch.PublicCertSecret, render.ElasticsearchManagerUserSecret,
			render.VoltronTunnelSecretName, render.ComplianceServerCertSecret, render.PacketCaptureCertSecret,
			render.ManagerInternalTLSSecretName, monitor.PrometheusTLSSecretName, certificatemanagement.CASecretName,
		} {
			if err = utils.AddSecretsWatch(c, secretName, namespace); err != nil {
				return fmt.Errorf("manager-controller failed to watch the secret '%s' in '%s' namespace: %w", secretName, namespace, err)
			}
		}
	}

	// This may or may not exist, it depends on what the OIDC type is in the Authentication CR.
	if err = utils.AddConfigMapWatch(c, tigerakvc.StaticWellKnownJWKSConfigMapName, common.OperatorNamespace()); err != nil {
		return fmt.Errorf("manager-controller failed to watch ConfigMap resource %s: %w", tigerakvc.StaticWellKnownJWKSConfigMapName, err)
	}

	if err = utils.AddConfigMapWatch(c, relasticsearch.ClusterConfigConfigMapName, common.OperatorNamespace()); err != nil {
		return fmt.Errorf("compliance-controller failed to watch the ConfigMap resource: %w", err)
	}

	if err = utils.AddNetworkWatch(c); err != nil {
		return fmt.Errorf("manager-controller failed to watch Network resource: %w", err)
	}

	if err = imageset.AddImageSetWatch(c); err != nil {
		return fmt.Errorf("manager-controller failed to watch ImageSet: %w", err)
	}

	if err = utils.AddNamespaceWatch(c, common.TigeraPrometheusNamespace); err != nil {
		return fmt.Errorf("manager-controller failed to watch the '%s' namespace: %w", common.TigeraPrometheusNamespace, err)
	}

	// Watch for changes to primary resource ManagementCluster
	err = c.Watch(&source.Kind{Type: &operatorv1.ManagementCluster{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("manager-controller failed to watch primary resource: %w", err)
	}

	// Watch for changes to primary resource ManagementClusterConnection
	err = c.Watch(&source.Kind{Type: &operatorv1.ManagementClusterConnection{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("manager-controller failed to watch primary resource: %w", err)
	}

	err = c.Watch(&source.Kind{Type: &operatorv1.Authentication{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return fmt.Errorf("manager-controller failed to watch resource: %w", err)
	}

	if err = utils.AddConfigMapWatch(c, render.ECKLicenseConfigMapName, render.ECKOperatorNamespace); err != nil {
		return fmt.Errorf("manager-controller failed to watch the ConfigMap resource: %v", err)
	}

	// Watch for changes to TigeraStatus.
	if err = utils.AddTigeraStatusWatch(c, ResourceName); err != nil {
		return fmt.Errorf("manager-controller failed to watch manager Tigerastatus: %w", err)
	}

	return nil
}

var _ reconcile.Reconciler = &ReconcileManager{}

// ReconcileManager reconciles a Manager object.
type ReconcileManager struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client          client.Client
	scheme          *runtime.Scheme
	provider        operatorv1.Provider
	status          status.StatusManager
	clusterDomain   string
	licenseAPIReady *utils.ReadyFlag
	tierWatchReady  *utils.ReadyFlag
	usePSP          bool
}

// GetManager returns the default manager instance with defaults populated.
func GetManager(ctx context.Context, cli client.Client) (*operatorv1.Manager, error) {
	// Fetch the manager instance. We only support a single instance named "tigera-secure".
	instance := &operatorv1.Manager{}
	err := cli.Get(ctx, utils.DefaultTSEEInstanceKey, instance)
	if err != nil {
		return nil, err
	}
	if instance.Spec.Auth != nil && instance.Spec.Auth.Type != operatorv1.AuthTypeToken {
		return nil, fmt.Errorf("auth types other than 'Token' can no longer be configured using the Manager CR, " +
			"please use the Authentication CR instead")
	}
	return instance, nil
}

// Reconcile reads that state of the cluster for a Manager object and makes changes based on the state read
// and what is in the Manager.Spec
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileManager) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	// Perform any common preparation that needs to be done for single-tenant and multi-tenant scenarios.
	logc := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	logc.Info("Reconciling Manager")

	// Fetch the Manager instance
	instance, err := GetManager(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			logc.Info("Manager object not found")
			r.status.OnCRNotFound()
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying Manager", err, logc)
		return reconcile.Result{}, err
	}
	logc.V(2).Info("Loaded config", "config", instance)
	r.status.OnCRFound()

	// SetMetaData in the TigeraStatus such as observedGenerations.
	defer r.status.SetMetaData(&instance.ObjectMeta)

	// Changes for updating Manager status conditions.
	if request.Name == ResourceName && request.Namespace == "" {
		ts := &operatorv1.TigeraStatus{}
		err := r.client.Get(ctx, types.NamespacedName{Name: ResourceName}, ts)
		if err != nil {
			return reconcile.Result{}, err
		}
		instance.Status.Conditions = status.UpdateStatusCondition(instance.Status.Conditions, ts.Status.Conditions)
		if err := r.client.Status().Update(ctx, instance); err != nil {
			log.WithValues("reason", err).Info("Failed to create Manager status conditions.")
			return reconcile.Result{}, err
		}
	}

	if !utils.IsAPIServerReady(r.client, logc) {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Tigera API server to be ready", nil, logc)
		return reconcile.Result{}, nil
	}

	// Validate that the tier watch is ready before querying the tier to ensure we utilize the cache.
	if !r.tierWatchReady.IsReady() {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for Tier watch to be established", nil, logc)
		return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
	}

	// Ensure the allow-tigera tier exists, before rendering any network policies within it.
	if err := r.client.Get(ctx, client.ObjectKey{Name: networkpolicy.TigeraComponentTierName}, &v3.Tier{}); err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for allow-tigera tier to be created", err, logc)
			return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
		} else {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying allow-tigera tier", err, logc)
			return reconcile.Result{}, err
		}
	}

	if !r.licenseAPIReady.IsReady() {
		r.status.SetDegraded(operatorv1.ResourceNotReady, "Waiting for LicenseKeyAPI to be ready", nil, logc)
		return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
	}

	license, err := utils.FetchLicenseKey(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "License not found", err, logc)
			return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying license", err, logc)
		return reconcile.Result{RequeueAfter: 10 * time.Second}, nil
	}

	// Fetch the Installation request.instance. We need this for a few reasons.
	// - We need to make sure it has successfully completed installation.
	// - We need to get the registry information from its spec.
	variant, installation, err := utils.GetInstallation(ctx, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "Installation not found", err, logc)
			return reconcile.Result{}, err
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying installation", err, logc)
		return reconcile.Result{}, err
	}

	// TODO: Query tenant(s) and include in the request. Or, call reconcileInstance multiple times
	// if a change requires a rollout to every tenant.

	// Package up the request parameters needed to reconcile
	req := Request{
		instance:       instance,
		NamespacedName: request.NamespacedName,
		variant:        variant,
		installation:   installation,
		license:        license,
	}

	return r.reconcileInstance(ctx, logc, req)
}

type Request struct {
	// The name and namespace of the object that triggered this request.
	types.NamespacedName

	// The Namespace of the objects to be deployed by this request.
	// For single-tenant installations, this will be tigera-manager.
	// For multi-tenant installations, this will be the tenant's namespace.
	ManagerNamespace string

	instance     *operatorv1.Manager
	variant      operatorv1.ProductVariant
	installation *operatorv1.InstallationSpec
	license      v3.LicenseKey
	tenantID     string
}

// TruthNamespace returns the namespace to use as the source of truth for storing data.
// For single-tenant installs, this is the tigera-operator namespace.
// For multi-tenant installs, this is tenant's namespace.
func (r *Request) TruthNamespace() string {
	if r.tenantID == "" {
		return common.OperatorNamespace()
	}
	return r.tenantID
}

func (r *ReconcileManager) reconcileInstance(ctx context.Context, logc logr.Logger, request Request) (reconcile.Result, error) {
	certificateManager, err := certificatemanager.Create(r.client, request.installation, r.clusterDomain)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceCreateError, "Unable to create the Tigera CA", err, logc)
		return reconcile.Result{}, err
	}

	// Get or create a certificate for clients of the manager pod es-proxy container.
	svcDNSNames := append(dns.GetServiceDNSNames(render.ManagerServiceName, render.ManagerNamespace, r.clusterDomain), "localhost")
	tlsSecret, err := certificateManager.GetOrCreateKeyPair(
		r.client,
		render.ManagerTLSSecretName,
		request.TruthNamespace(),
		svcDNSNames)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error getting or creating manager TLS certificate", err, logc)
		return reconcile.Result{}, err
	}

	// Determine if compliance is enabled.
	complianceLicenseFeatureActive := utils.IsFeatureActive(request.license, common.ComplianceFeature)
	complianceCR, err := compliance.GetCompliance(ctx, r.client)
	if err != nil && !errors.IsNotFound(err) {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying compliance: ", err, logc)
		return reconcile.Result{}, err
	}

	// Build a trusted bundle containing all of the certificates of components that communicate with the manager pod.
	// This bundle contains the root CA used to sign all operator-generated certificates, as well as the explicitly named
	// certificates, in case the user has provided their own cert in lieu of the default certificate.
	trustedSecretNames := []string{
		render.PacketCaptureCertSecret,
		monitor.PrometheusTLSSecretName,
		relasticsearch.PublicCertSecret,
		render.ProjectCalicoAPIServerTLSSecretName(request.installation.Variant),
		render.TigeraLinseedSecret,
	}
	if complianceLicenseFeatureActive && complianceCR != nil {
		// Check that compliance is running.
		if complianceCR.Status.State != operatorv1.TigeraStatusReady {
			r.status.SetDegraded(operatorv1.ResourceNotReady, "Compliance is not ready", nil, logc)
			return reconcile.Result{}, nil
		}
		trustedSecretNames = append(trustedSecretNames, render.ComplianceServerCertSecret)
	}

	// Fetch the Authentication spec. If present, we use to configure user authentication.
	authenticationCR, err := utils.GetAuthentication(ctx, r.client)
	if err != nil && !errors.IsNotFound(err) {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error while fetching Authentication", err, logc)
		return reconcile.Result{}, err
	}
	if authenticationCR != nil && authenticationCR.Status.State != operatorv1.TigeraStatusReady {
		r.status.SetDegraded(operatorv1.ResourceNotReady, fmt.Sprintf("Authentication is not ready authenticationCR status: %s", authenticationCR.Status.State), nil, logc)
		return reconcile.Result{}, nil
	} else if authenticationCR != nil {
		trustedSecretNames = append(trustedSecretNames, render.DexTLSSecretName)
	}

	// TODO: Trusted bundle for all components will be in the same namespace for multi-tenancy.
	// So, we'll need to refactor this. I think for multi-tenancy, we can simplify the trusted-bundle generation
	// altogether so that we only ever need a single cert for it. In single-tenant, we need more complexity in order
	// to support BYO certs.
	//
	// That said, it's probably a good idea to move certificate management to its own controller anyway so that
	// it's not so scattered!
	trustedBundle := certificateManager.CreateTrustedBundle()
	for _, secretName := range trustedSecretNames {
		certificate, err := certificateManager.GetCertificate(r.client, secretName, request.TruthNamespace())
		if err != nil {
			r.status.SetDegraded(operatorv1.CertificateError, fmt.Sprintf("Failed to retrieve %s", secretName), err, logc)
			return reconcile.Result{}, err
		} else if certificate == nil {
			logc.Info(fmt.Sprintf("Waiting for secret '%s' to become available", secretName))
			r.status.SetDegraded(operatorv1.ResourceNotReady, fmt.Sprintf("Waiting for secret '%s' to become available", secretName), nil, logc)
			return reconcile.Result{}, nil
		}
		trustedBundle.AddCertificates(certificate)
	}
	certificateManager.AddToStatusManager(r.status, render.ManagerNamespace)

	// Check that Prometheus is running
	// TODO: We'll need to run an instance of Prometheus per-tenant? Or do we use labels to delimit metrics?
	//       Probably the former.
	ns := &corev1.Namespace{}
	if err = r.client.Get(ctx, client.ObjectKey{Name: common.TigeraPrometheusNamespace}, ns); err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "tigera-prometheus namespace does not exist Dependency on tigera-prometheus not satisfied", nil, logc)
		} else {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error querying prometheus", err, logc)
		}
		return reconcile.Result{}, err
	}

	pullSecrets, err := utils.GetNetworkingPullSecrets(request.installation, r.client)
	if err != nil {
		log.Error(err, "Error with Pull secrets")
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error retrieving pull secrets", err, logc)
		return reconcile.Result{}, err
	}

	esClusterConfig, err := utils.GetElasticsearchClusterConfig(context.Background(), r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "Elasticsearch cluster configuration is not available, waiting for it to become available", err, logc)
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to get the elasticsearch cluster configuration", err, logc)
		return reconcile.Result{}, err
	}

	// Get secrets used by the manager to authenticate with Elasticsearch.
	// TODO: esSecrets should be namespaced in the tenant's namespace. We can't get rid of this 100%
	// since some secrets are needed for Kibana auth flow.
	esSecrets, err := utils.ElasticsearchSecrets(ctx, []string{render.ElasticsearchManagerUserSecret}, r.client)
	if err != nil {
		if errors.IsNotFound(err) {
			r.status.SetDegraded(operatorv1.ResourceNotFound, "Elasticsearch secrets are not available yet, waiting until they become available", err, logc)
			return reconcile.Result{}, nil
		}
		r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to get Elasticsearch credentials", err, logc)
		return reconcile.Result{}, err
	}

	managementCluster, err := utils.GetManagementCluster(ctx, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error reading ManagementCluster", err, logc)
		return reconcile.Result{}, err
	}

	managementClusterConnection, err := utils.GetManagementClusterConnection(ctx, r.client)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceReadError, "Error reading ManagementClusterConnection", err, logc)
		return reconcile.Result{}, err
	}

	if managementClusterConnection != nil && managementCluster != nil {
		err = fmt.Errorf("having both a ManagementCluster and a ManagementClusterConnection is not supported")
		r.status.SetDegraded(operatorv1.ResourceValidationError, "", err, logc)
		return reconcile.Result{}, err
	}

	var tunnelSecret certificatemanagement.KeyPairInterface
	var internalTrafficSecret certificatemanagement.KeyPairInterface
	var linseedVoltronSecret certificatemanagement.KeyPairInterface
	if managementCluster != nil {
		preDefaultPatchFrom := client.MergeFrom(managementCluster.DeepCopy())
		fillDefaults(managementCluster)

		// Write the discovered configuration back to the API. This is essentially a poor-man's defaulting, and
		// ensures that we don't surprise anyone by changing defaults in a future version of the operator.
		if err := r.client.Patch(ctx, managementCluster, preDefaultPatchFrom); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "", err, logc)
			return reconcile.Result{}, err
		}

		// Create a certificate for Voltron to use for TLS connections from the managed cluster destined
		// to Linseed. This certificate is used only for connections received over Voltron's mTLS tunnel targeting tigera-linseed.
		linseedDNSNames := dns.GetServiceDNSNames(render.LinseedServiceName, render.ElasticsearchNamespace, r.clusterDomain)
		linseedVoltronSecret, err = certificateManager.GetOrCreateKeyPair(
			r.client,
			render.VoltronLinseedTLS,
			request.TruthNamespace(),
			linseedDNSNames)
		if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Error getting or creating Voltron Linseed TLS certificate", err, logc)
			return reconcile.Result{}, err
		}

		// We expect that the secret that holds the certificates for tunnel certificate generation
		// is already created by the API server.
		// TODO: Need to make sure this secret is generated in per-tenant namespace.
		tunnelSecret, err = certificateManager.GetKeyPair(r.client, render.VoltronTunnelSecretName, request.TruthNamespace())
		if tunnelSecret == nil {
			r.status.SetDegraded(operatorv1.ResourceNotReady, fmt.Sprintf("Waiting for secret %s in namespace %s to be available", render.VoltronTunnelSecretName, request.TruthNamespace()), nil, logc)
			return reconcile.Result{}, err
		} else if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, fmt.Sprintf("Error fetching TLS secret %s in namespace %s", render.VoltronTunnelSecretName, request.TruthNamespace()), err, logc)
			return reconcile.Result{}, nil
		}

		// We expect that the secret that holds the certificates for internal communication within the management
		// K8S cluster is already created by kube-controllers.
		internalTrafficSecret, err = certificateManager.GetKeyPair(r.client, render.ManagerInternalTLSSecretName, request.TruthNamespace())
		if internalTrafficSecret == nil {
			r.status.SetDegraded(operatorv1.ResourceNotReady, fmt.Sprintf("Waiting for secret %s in namespace %s to be available", render.ManagerInternalTLSSecretName, request.TruthNamespace()), nil, logc)
			return reconcile.Result{}, err
		} else if err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, fmt.Sprintf("Error fetching TLS secret %s in namespace %s", render.ManagerInternalTLSSecretName, request.TruthNamespace()), err, logc)
			return reconcile.Result{}, nil
		}

		// Es-proxy needs to trust Voltron for cross-cluster requests.
		trustedBundle.AddCertificates(internalTrafficSecret)
	}

	keyValidatorConfig, err := utils.GetKeyValidatorConfig(ctx, r.client, authenticationCR, r.clusterDomain)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceValidationError, "Failed to process the authentication CR.", err, logc)
		return reconcile.Result{}, err
	}

	var elasticLicenseType render.ElasticsearchLicenseType
	if managementClusterConnection == nil {
		if elasticLicenseType, err = utils.GetElasticLicenseType(ctx, r.client, logc); err != nil {
			r.status.SetDegraded(operatorv1.ResourceReadError, "Failed to get Elasticsearch license", err, logc)
			return reconcile.Result{}, err
		}
	}

	// Create a component handler to manage the rendered component.
	handler := utils.NewComponentHandler(log, r.client, r.scheme, request.instance)

	// Set replicas to 1 for management or managed clusters.
	// TODO Remove after MCM tigera-manager HA deployment is supported.
	var replicas *int32 = request.installation.ControlPlaneReplicas
	if managementCluster != nil || managementClusterConnection != nil {
		var mcmReplicas int32 = 1
		replicas = &mcmReplicas
	}

	managerCfg := &render.ManagerConfiguration{
		KeyValidatorConfig:      keyValidatorConfig,
		ESSecrets:               esSecrets,
		TrustedCertBundle:       trustedBundle,
		ESClusterConfig:         esClusterConfig,
		TLSKeyPair:              tlsSecret,
		VoltronLinseedKeyPair:   linseedVoltronSecret,
		PullSecrets:             pullSecrets,
		Openshift:               r.provider == operatorv1.ProviderOpenShift,
		Installation:            request.installation,
		ManagementCluster:       managementCluster,
		TunnelSecret:            tunnelSecret,
		InternalTrafficSecret:   internalTrafficSecret,
		ClusterDomain:           r.clusterDomain,
		ESLicenseType:           elasticLicenseType,
		Replicas:                replicas,
		Compliance:              complianceCR,
		ComplianceLicenseActive: complianceLicenseFeatureActive,
		UsePSP:                  r.usePSP,
	}

	// Render the desired objects from the CRD and create or update them.
	component, err := render.Manager(managerCfg)
	if err != nil {
		r.status.SetDegraded(operatorv1.ResourceRenderingError, "Error rendering Manager", err, logc)
		return reconcile.Result{}, err
	}
	component = render.NewTenantIsolater(component)

	if err = imageset.ApplyImageSet(ctx, r.client, request.variant, component); err != nil {
		r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error with images from ImageSet", err, logc)
		return reconcile.Result{}, err
	}

	components := []render.Component{
		component,
		rcertificatemanagement.CertificateManagement(&rcertificatemanagement.Config{
			Namespace:       render.ManagerNamespace, // TODO: Needs to be updated.
			ServiceAccounts: []string{render.ManagerServiceAccount},
			KeyPairOptions: []rcertificatemanagement.KeyPairOption{
				rcertificatemanagement.NewKeyPairOption(tlsSecret, true, true),
				rcertificatemanagement.NewKeyPairOption(linseedVoltronSecret, true, true),
				rcertificatemanagement.NewKeyPairOption(internalTrafficSecret, false, true),
				rcertificatemanagement.NewKeyPairOption(tunnelSecret, false, true),
			},
			TrustedBundle: trustedBundle,
		}),
	}
	for _, component := range components {
		if err := handler.CreateOrUpdateOrDelete(ctx, component, r.status); err != nil {
			r.status.SetDegraded(operatorv1.ResourceUpdateError, "Error creating / updating resource", err, logc)
			return reconcile.Result{}, err
		}
	}

	// Clear the degraded bit if we've reached this far.
	r.status.ClearDegraded()
	request.instance.Status.State = operatorv1.TigeraStatusReady
	if r.status.IsAvailable() {
		if err = r.client.Status().Update(ctx, request.instance); err != nil {
			return reconcile.Result{}, err
		}
	}

	return reconcile.Result{}, nil
}

func fillDefaults(mc *operatorv1.ManagementCluster) {
	if mc.Spec.TLS == nil {
		mc.Spec.TLS = &operatorv1.TLS{}
	}
	if mc.Spec.TLS.SecretName == "" {
		mc.Spec.TLS.SecretName = render.VoltronTunnelSecretName
	}
}
