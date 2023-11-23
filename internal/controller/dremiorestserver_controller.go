/*
Copyright 2023.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	operatorv1 "github.com/scc-digitalhub/dremio-rest-server-operator/api/v1"
)

const dremioRestServerImage = "DRS_IMAGE"
const dremioRestServerImageTag = "DRS_IMAGE_TAG"
const dremioRestServerServiceType = "DRS_SERVICE_TYPE"
const dremioRestServerUri = "DRS_DREMIO_URI"

// Definitions to manage status conditions
const (
	// Launch deployment and service
	typeDeploying = "Deploying"

	typeRunning = "Running"

	typeError = "Error"

	typeUpdating = "Updating"
)

// DremioRestServerReconciler reconciles a DremioRestServer object
type DremioRestServerReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

func formatResourceName(resourceName string) string {
	return strings.Join([]string{"dremiorestserver", resourceName}, "-")
}

//+kubebuilder:rbac:groups=operator.dremiorestserver.com,namespace=dremions,resources=dremiorestservers,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=operator.dremiorestserver.com,namespace=dremions,resources=dremiorestservers/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=apps,namespace=dremions,resources=deployments,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,namespace=dremions,resources=pods,verbs=get;list;watch
//+kubebuilder:rbac:groups=core,namespace=dremions,resources=services,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,namespace=dremions,resources=secrets,verbs=get;list;watch;create;update;patch;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.14.1/pkg/reconcile
func (r *DremioRestServerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	// Fetch the DremioRestServer instance
	// The purpose is check if the Custom Resource for the Kind DremioRestServer
	// is applied on the cluster if not we return nil to stop the reconciliation
	dremiorestserver := &operatorv1.DremioRestServer{}
	err := r.Get(ctx, req.NamespacedName, dremiorestserver)
	if err != nil {
		if apierrors.IsNotFound(err) {
			// If the custom resource is not found then, it usually means that it was deleted or not created
			// In this way, we will stop the reconciliation
			log.Info("dremiorestserver resource not found. Ignoring since object must be deleted")
			return ctrl.Result{}, nil
		}
		// Error reading the object - requeue the request.
		log.Error(err, "Failed to get dremiorestserver")
		return ctrl.Result{}, err
	}

	// If status is unknown, set Deploying
	if dremiorestserver.Status.State == "" {
		log.Info("State unspecified, updating to deploying")
		dremiorestserver.Status.State = typeDeploying
		if err = r.Status().Update(ctx, dremiorestserver); err != nil {
			log.Error(err, "failed to update DremioRestServer status")
			return ctrl.Result{}, err
		}

		return ctrl.Result{Requeue: true}, nil
	}

	if dremiorestserver.Status.State == typeDeploying {
		log.Info("Deploying and creating service")

		// Get or create secret
		existingSecret := &corev1.Secret{}
		err = r.Get(ctx, types.NamespacedName{Name: formatResourceName(dremiorestserver.Name), Namespace: dremiorestserver.Namespace}, existingSecret)
		if err != nil && apierrors.IsNotFound(err) {
			// Create secret
			secret, err := r.secretForDremiorestserver(dremiorestserver)
			if err != nil {
				log.Error(err, "Failed to define new Secret resource for DremioRestServer")

				dremiorestserver.Status.State = typeError

				if err := r.Status().Update(ctx, dremiorestserver); err != nil {
					log.Error(err, "failed to update DremioRestServer status")
					return ctrl.Result{}, err
				}

				return ctrl.Result{}, err
			}
			log.Info("Creating a new Secret", "Secret.Namespace", secret.Namespace, "Secret.Name", secret.Name)
			if err = r.Create(ctx, secret); err != nil {
				log.Error(err, "Failed to create new Secret", "Secret.Namespace", secret.Namespace, "Secret.Name", secret.Name)
				return ctrl.Result{}, err
			}
		} else if err != nil {
			log.Error(err, "Failed to get secret")
			// Return error for reconciliation to be re-trigged
			return ctrl.Result{}, err
		}

		// Check if the deployment already exists, if not create a new one
		found := &appsv1.Deployment{}
		err = r.Get(ctx, types.NamespacedName{Name: formatResourceName(dremiorestserver.Name), Namespace: dremiorestserver.Namespace}, found)
		if err != nil && apierrors.IsNotFound(err) {
			// Define a new deployment
			dep, err := r.deploymentForDremiorestserver(dremiorestserver)
			if err != nil {
				log.Error(err, "Failed to define new Deployment resource for DremioRestServer")

				dremiorestserver.Status.State = typeError

				if err := r.Status().Update(ctx, dremiorestserver); err != nil {
					log.Error(err, "failed to update DremioRestServer status")
					return ctrl.Result{}, err
				}

				return ctrl.Result{}, err
			}

			log.Info("Creating a new Deployment",
				"Deployment.Namespace", dep.Namespace, "Deployment.Name", dep.Name)
			if err = r.Create(ctx, dep); err != nil {
				log.Error(err, "Failed to create new Deployment",
					"Deployment.Namespace", dep.Namespace, "Deployment.Name", dep.Name)
				return ctrl.Result{}, err
			}
		} else if err != nil {
			log.Error(err, "failed to get deployment")
			// Return error for reconciliation to be re-trigged
			return ctrl.Result{}, err
		}

		// Create service
		existingService := &corev1.Service{}
		err = r.Get(ctx, types.NamespacedName{Name: formatResourceName(dremiorestserver.Name), Namespace: dremiorestserver.Namespace}, existingService)
		if err != nil && apierrors.IsNotFound(err) {
			service, err := r.serviceForDremiorestserver(dremiorestserver)
			if err != nil {
				log.Error(err, "Service inizialition failed")

				dremiorestserver.Status.State = typeError

				if err := r.Status().Update(ctx, dremiorestserver); err != nil {
					log.Error(err, "failed to update DremioRestServer status")
					return ctrl.Result{}, err
				}

				return ctrl.Result{}, err
			}
			log.Info("Creating a new Service", "Service.Namespace", service.Namespace, "Service.Name", service.Name)
			if err = r.Create(ctx, service); err != nil {
				log.Error(err, "Service creation failed")
				return ctrl.Result{}, err
			}
		} else if err != nil {
			log.Error(err, "failed to get service")
			// Return error for reconciliation to be re-trigged
			return ctrl.Result{}, err
		}

		dremiorestserver.Status.State = typeRunning
		if err = r.Status().Update(ctx, dremiorestserver); err != nil {
			log.Error(err, "failed to update DremioRestServer status")
			return ctrl.Result{}, err
		}

		log.Info("Deployment and service created successfully")
		// Deployment created successfully
		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}

	if dremiorestserver.Status.State == typeRunning {
		dep := &appsv1.Deployment{}
		err = r.Get(ctx, types.NamespacedName{Name: formatResourceName(dremiorestserver.Name), Namespace: dremiorestserver.Namespace}, dep)
		if err != nil {
			log.Error(err, "error while retrieving deployment")
			return ctrl.Result{}, err
		}

		updated := crUpdated(dep, dremiorestserver)
		if updated {
			dremiorestserver.Status.State = typeUpdating
			if err = r.Status().Update(ctx, dremiorestserver); err != nil {
				log.Error(err, "failed to update DremioRestServer status")
				return ctrl.Result{}, err
			}
		}

		// Deployment ready
		if dep.Status.ReadyReplicas > 0 {
			log.Info("Deployment is ready")
			if err = r.Status().Update(ctx, dremiorestserver); err != nil {
				log.Error(err, "failed to update DremioRestServer status")
				return ctrl.Result{}, err
			}

			return ctrl.Result{}, nil
		}

		// Wait up to 15 minutes for deployment to become ready
		if dep.CreationTimestamp.Add(15 * time.Minute).Before(time.Now()) {
			log.Info("Deployment still not ready, setting state to Error")
			dremiorestserver.Status.State = typeError

			if err = r.Status().Update(ctx, dremiorestserver); err != nil {
				log.Error(err, "failed to update DremioRestServer status")
				return ctrl.Result{}, err
			}
			return ctrl.Result{Requeue: true}, nil
		}

		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}

	if dremiorestserver.Status.State == typeUpdating {
		log.Info("Updating: deleting previous deployment")

		// Delete deployment
		deployment := &appsv1.Deployment{}
		err = r.Get(ctx, types.NamespacedName{Name: formatResourceName(dremiorestserver.Name), Namespace: dremiorestserver.Namespace}, deployment)
		if err == nil {
			if err := r.Delete(ctx, deployment); err != nil {
				log.Error(err, "Failed to clean up deployment")
			}
		} else if err != nil && !apierrors.IsNotFound(err) {
			log.Error(err, "Failed to get deployment")
			// Return error for reconciliation to be re-trigged
			return ctrl.Result{}, err
		}

		// Move to deploying state
		dremiorestserver.Status.State = typeDeploying
		if err = r.Status().Update(ctx, dremiorestserver); err != nil {
			log.Error(err, "failed to update DremioRestServer status")
			return ctrl.Result{}, err
		}

		return ctrl.Result{Requeue: true}, nil
	}

	if dremiorestserver.Status.State == typeError {
		log.Info("Cleaning up secret, deployment and service")

		// Delete service
		service := &corev1.Service{}
		err = r.Get(ctx, types.NamespacedName{Name: formatResourceName(dremiorestserver.Name), Namespace: dremiorestserver.Namespace}, service)
		if err == nil {
			if err := r.Delete(ctx, service); err != nil {
				log.Error(err, "Failed to clean up service")
			}
		} else if err != nil && !apierrors.IsNotFound(err) {
			log.Error(err, "Failed to get service")
			// Return error for reconciliation to be re-trigged
			return ctrl.Result{}, err
		}

		// Delete deployment
		deployment := &appsv1.Deployment{}
		err = r.Get(ctx, types.NamespacedName{Name: formatResourceName(dremiorestserver.Name), Namespace: dremiorestserver.Namespace}, deployment)
		if err == nil {
			if err := r.Delete(ctx, deployment); err != nil {
				log.Error(err, "Failed to clean up deployment")
			}
		} else if err != nil && !apierrors.IsNotFound(err) {
			log.Error(err, "Failed to get deployment")
			// Return error for reconciliation to be re-trigged
			return ctrl.Result{}, err
		}

		// Delete secret
		secret := &corev1.Secret{}
		err = r.Get(ctx, types.NamespacedName{Name: formatResourceName(dremiorestserver.Name), Namespace: dremiorestserver.Namespace}, secret)
		if err == nil {
			if err := r.Delete(ctx, secret); err != nil {
				log.Error(err, "Failed to clean up secret")
			}
		} else if err != nil && !apierrors.IsNotFound(err) {
			log.Error(err, "Failed to get secret")
			// Return error for reconciliation to be re-trigged
			return ctrl.Result{}, err
		}

		return ctrl.Result{}, nil
	}

	return ctrl.Result{}, nil
}

func crUpdated(dep *appsv1.Deployment, cr *operatorv1.DremioRestServer) bool {
	// Check if CR spec (JavaOptions, Tables, ContainerLimits, ContainerRequests) has been modified
	for _, env := range dep.Spec.Template.Spec.Containers[0].Env {
		if env.Name == "JAVA_TOOL_OPTIONS" {
			// Compare with current JavaOptions
			if cr.Spec.JavaOptions != env.Value {
				return true
			}
		}
		if env.Name == "DREMIO_TABLES" {
			// Compare with current Tables
			if cr.Spec.Tables != env.Value {
				return true
			}
		}
	}

	resources := dep.Spec.Template.Spec.Containers[0].Resources

	if cr.Spec.ContainerLimits.Cpu == "" {
		if !resources.Limits.Cpu().IsZero() {
			return true
		}
	} else if !resources.Limits.Cpu().Equal(resource.MustParse(cr.Spec.ContainerLimits.Cpu)) {
		return true
	}

	if cr.Spec.ContainerLimits.Memory == "" {
		if !resources.Limits.Memory().IsZero() {
			return true
		}
	} else if !resources.Limits.Memory().Equal(resource.MustParse(cr.Spec.ContainerLimits.Memory)) {
		return true
	}

	if cr.Spec.ContainerRequests.Cpu == "" {
		if !resources.Requests.Cpu().IsZero() {
			return true
		}
	} else if !resources.Requests.Cpu().Equal(resource.MustParse(cr.Spec.ContainerRequests.Cpu)) {
		return true
	}

	if cr.Spec.ContainerRequests.Memory == "" {
		if !resources.Requests.Memory().IsZero() {
			return true
		}
	} else if !resources.Requests.Memory().Equal(resource.MustParse(cr.Spec.ContainerRequests.Memory)) {
		return true
	}

	return false
}

// deploymentForDremiorestserver returns a DremioRestServer Deployment object
func (r *DremioRestServerReconciler) deploymentForDremiorestserver(
	dremiorestserver *operatorv1.DremioRestServer) (*appsv1.Deployment, error) {
	image, found := os.LookupEnv(dremioRestServerImage)
	if !found {
		image = "ghcr.io/scc-digitalhub/dremio-rest-server"
	}
	tag, found := os.LookupEnv(dremioRestServerImageTag)
	if !found {
		tag = "latest"
	}

	if dremiorestserver.Spec.Tables == "" {
		return nil, errors.New("tables missing from spec")
	}

	//leave limits and requests empty by default
	limits := corev1.ResourceList{}
	if dremiorestserver.Spec.ContainerLimits.Cpu != "" {
		limits[corev1.ResourceCPU] = resource.MustParse(dremiorestserver.Spec.ContainerLimits.Cpu)
	}
	if dremiorestserver.Spec.ContainerLimits.Memory != "" {
		limits[corev1.ResourceMemory] = resource.MustParse(dremiorestserver.Spec.ContainerLimits.Memory)
	}

	requests := corev1.ResourceList{}
	if dremiorestserver.Spec.ContainerRequests.Cpu != "" {
		requests[corev1.ResourceCPU] = resource.MustParse(dremiorestserver.Spec.ContainerRequests.Cpu)
	}
	if dremiorestserver.Spec.ContainerRequests.Memory != "" {
		requests[corev1.ResourceMemory] = resource.MustParse(dremiorestserver.Spec.ContainerRequests.Memory)
	}

	ls := labelsForDremioRestServer(dremiorestserver.Name, tag)
	selectors := selectorsForDremioRestServer(dremiorestserver.Name)

	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      formatResourceName(dremiorestserver.Name),
			Namespace: dremiorestserver.Namespace,
			Labels:    ls,
		},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: selectors,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: ls,
				},
				Spec: corev1.PodSpec{
					// TODO(user): Uncomment the following code to configure the nodeAffinity expression
					// according to the platforms which are supported by your solution. It is considered
					// best practice to support multiple architectures. build your manager image using the
					// makefile target docker-buildx. Also, you can use docker manifest inspect <image>
					// to check what are the platforms supported.
					// More info: https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#node-affinity
					//Affinity: &corev1.Affinity{
					//	NodeAffinity: &corev1.NodeAffinity{
					//		RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
					//			NodeSelectorTerms: []corev1.NodeSelectorTerm{
					//				{
					//					MatchExpressions: []corev1.NodeSelectorRequirement{
					//						{
					//							Key:      "kubernetes.io/arch",
					//							Operator: "In",
					//							Values:   []string{"amd64", "arm64", "ppc64le", "s390x"},
					//						},
					//						{
					//							Key:      "kubernetes.io/os",
					//							Operator: "In",
					//							Values:   []string{"linux"},
					//						},
					//					},
					//				},
					//			},
					//		},
					//	},
					//},
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot: &[]bool{true}[0],
						// IMPORTANT: seccomProfile was introduced with Kubernetes 1.19
						// If you are looking for to produce solutions to be supported
						// on lower versions you must remove this option.
						SeccompProfile: &corev1.SeccompProfile{
							Type: corev1.SeccompProfileTypeRuntimeDefault,
						},
					},
					Containers: []corev1.Container{{
						Image:           strings.Join([]string{image, tag}, ":"),
						Name:            "dremiorestserver",
						ImagePullPolicy: corev1.PullIfNotPresent,
						Resources: corev1.ResourceRequirements{
							Limits:   limits,
							Requests: requests,
						},
						// Ensure restrictive context for the container
						// More info: https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted
						SecurityContext: &corev1.SecurityContext{
							AllowPrivilegeEscalation: &[]bool{false}[0],
							Capabilities: &corev1.Capabilities{
								Drop: []corev1.Capability{
									"ALL",
								},
							},
							ReadOnlyRootFilesystem: &[]bool{true}[0],
						},
						Env: []corev1.EnvVar{
							{
								Name:  "JAVA_TOOL_OPTIONS",
								Value: dremiorestserver.Spec.JavaOptions,
							},
							{
								Name: "DREMIO_URL",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{Name: formatResourceName(dremiorestserver.Name)},
										Key:                  dremioRestServerUri,
										Optional:             &[]bool{false}[0],
									},
								},
							},
							{
								Name:  "DREMIO_TABLES",
								Value: dremiorestserver.Spec.Tables,
							},
						},
					}},
				},
			},
		},
	}

	// Set the ownerRef for the Deployment
	// More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/owners-dependents/
	if err := ctrl.SetControllerReference(dremiorestserver, dep, r.Scheme); err != nil {
		return nil, err
	}
	return dep, nil
}

func (r *DremioRestServerReconciler) serviceForDremiorestserver(dremiorestserver *operatorv1.DremioRestServer) (*corev1.Service, error) {
	tag, found := os.LookupEnv(dremioRestServerImageTag)
	if !found {
		tag = "latest"
	}

	var corev1ServiceType corev1.ServiceType
	serviceType, found := os.LookupEnv(dremioRestServerServiceType)
	if found && strings.EqualFold(serviceType, "ClusterIP") {
		corev1ServiceType = corev1.ServiceTypeClusterIP
	} else if !found || serviceType == "" || strings.EqualFold(serviceType, "NodePort") {
		corev1ServiceType = corev1.ServiceTypeNodePort
	} else {
		return nil, errors.New("invalid service type")
	}

	ls := labelsForDremioRestServer(dremiorestserver.Name, tag)
	selectors := selectorsForDremioRestServer(dremiorestserver.Name)

	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      formatResourceName(dremiorestserver.Name),
			Namespace: dremiorestserver.Namespace,
			Labels:    ls,
		},
		Spec: corev1.ServiceSpec{
			Selector: selectors,
			Type:     corev1ServiceType,
			Ports: []corev1.ServicePort{{
				Protocol:   corev1.ProtocolTCP,
				Port:       3000,
				TargetPort: intstr.FromInt(8080),
			}},
		},
	}

	if err := ctrl.SetControllerReference(dremiorestserver, service, r.Scheme); err != nil {
		return nil, err
	}

	return service, nil
}

func (r *DremioRestServerReconciler) secretForDremiorestserver(dremiorestserver *operatorv1.DremioRestServer) (*corev1.Secret, error) {
	dremioUri, found := os.LookupEnv(dremioRestServerUri)
	if !found {
		return nil, fmt.Errorf("dremio URI not specified, environment variable %v is required", dremioRestServerUri)
	}

	tag, found := os.LookupEnv(dremioRestServerImageTag)
	if !found {
		tag = "latest"
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      formatResourceName(dremiorestserver.Name),
			Namespace: dremiorestserver.Namespace,
			Labels:    labelsForDremioRestServer(dremiorestserver.Name, tag),
		},
		StringData: map[string]string{dremioRestServerUri: dremioUri},
	}

	if err := ctrl.SetControllerReference(dremiorestserver, secret, r.Scheme); err != nil {
		return nil, err
	}

	return secret, nil
}

// labelsForDremioRestServer returns the labels for selecting the resources
// More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/common-labels/
func labelsForDremioRestServer(name string, version string) map[string]string {
	selectors := selectorsForDremioRestServer(name)
	selectors["app.kubernetes.io/version"] = version
	selectors["app.kubernetes.io/part-of"] = "dremiorestserver"
	return selectors
}

func selectorsForDremioRestServer(name string) map[string]string {
	return map[string]string{"app.kubernetes.io/name": "DremioRestServer",
		"app.kubernetes.io/instance":   name,
		"app.kubernetes.io/managed-by": "dremiorestserver-operator",
	}
}

// SetupWithManager sets up the controller with the Manager.
// Note that the Deployment will be also watched in order to ensure its
// desirable state on the cluster
// TODO add Owns to other resources?
func (r *DremioRestServerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&operatorv1.DremioRestServer{}).
		Owns(&appsv1.Deployment{}).
		Complete(r)
}
