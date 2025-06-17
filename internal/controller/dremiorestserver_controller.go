// Copyright 2023.
// SPDX-FileCopyrightText: © 2025 DSLab - Fondazione Bruno Kessler
//
// SPDX-License-Identifier: Apache-2.0

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

const dremioUriSecretKey = "dremioUri"

const containerLimitsCpu = "DRS_CONTAINER_LIMITS_CPU"
const containerLimitsMemory = "DRS_CONTAINER_LIMITS_MEMORY"
const containerRequestsCpu = "DRS_CONTAINER_REQUESTS_CPU"
const containerRequestsMemory = "DRS_CONTAINER_REQUESTS_MEMORY"

const genericStatusUpdateFailedMessage = "failed to update DremioRestServer status"

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
	cr := &operatorv1.DremioRestServer{}
	err := r.Get(ctx, req.NamespacedName, cr)
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
	if cr.Status.State == "" {
		log.Info("State unspecified, updating to deploying")
		cr.Status.State = typeDeploying
		if err = r.Status().Update(ctx, cr); err != nil {
			log.Error(err, genericStatusUpdateFailedMessage)
			return ctrl.Result{}, err
		}

		return ctrl.Result{Requeue: true}, nil
	}

	if cr.Status.State == typeDeploying {
		log.Info("Creating secret, deployment and service")

		// Get or create secret
		existingSecret := &corev1.Secret{}
		err = r.Get(ctx, types.NamespacedName{Name: formatResourceName(cr.Name), Namespace: cr.Namespace}, existingSecret)
		if err != nil && apierrors.IsNotFound(err) {
			// Create secret
			secret, err := r.secretForDremiorestserver(cr, ctx)
			if err != nil {
				log.Error(err, "Failed to define new Secret resource for DremioRestServer")

				cr.Status.State = typeError

				if err := r.Status().Update(ctx, cr); err != nil {
					log.Error(err, genericStatusUpdateFailedMessage)
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
		err = r.Get(ctx, types.NamespacedName{Name: formatResourceName(cr.Name), Namespace: cr.Namespace}, found)
		if err != nil && apierrors.IsNotFound(err) {
			// Define a new deployment
			dep, err := r.deploymentForDremiorestserver(cr)
			if err != nil {
				log.Error(err, "Failed to define new Deployment resource for DremioRestServer")

				cr.Status.State = typeError

				if err := r.Status().Update(ctx, cr); err != nil {
					log.Error(err, genericStatusUpdateFailedMessage)
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
		err = r.Get(ctx, types.NamespacedName{Name: formatResourceName(cr.Name), Namespace: cr.Namespace}, existingService)
		if err != nil && apierrors.IsNotFound(err) {
			service, err := r.serviceForDremiorestserver(cr)
			if err != nil {
				log.Error(err, "Service inizialization failed")

				cr.Status.State = typeError

				if err := r.Status().Update(ctx, cr); err != nil {
					log.Error(err, genericStatusUpdateFailedMessage)
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

		cr.Status.State = typeRunning
		if err = r.Status().Update(ctx, cr); err != nil {
			log.Error(err, genericStatusUpdateFailedMessage)
			return ctrl.Result{}, err
		}

		log.Info("Deployment and service created successfully")
		// Deployment created successfully
		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}

	if cr.Status.State == typeRunning {
		// Check secret
		secret := &corev1.Secret{}
		err = r.Get(ctx, types.NamespacedName{Name: formatResourceName(cr.Name), Namespace: cr.Namespace}, secret)
		if err != nil {
			return handleMissingResource(r, ctx, cr, err)
		}

		// Check deployment
		dep := &appsv1.Deployment{}
		err = r.Get(ctx, types.NamespacedName{Name: formatResourceName(cr.Name), Namespace: cr.Namespace}, dep)
		if err != nil {
			return handleMissingResource(r, ctx, cr, err)
		}

		// Check service
		service := &corev1.Service{}
		err = r.Get(ctx, types.NamespacedName{Name: formatResourceName(cr.Name), Namespace: cr.Namespace}, service)
		if err != nil {
			return handleMissingResource(r, ctx, cr, err)
		}

		// Generate connection string and check if resource has been updated
		dremioUri, err := r.createConnectionString(cr, ctx)
		if err != nil {
			return ctrl.Result{}, err
		}

		updated := crUpdated(dep, cr, dremioUri, string(secret.Data[dremioUriSecretKey]))
		if updated {
			cr.Status.State = typeUpdating
			if err = r.Status().Update(ctx, cr); err != nil {
				log.Error(err, genericStatusUpdateFailedMessage)
				return ctrl.Result{}, err
			}
		}

		// Deployment ready
		if dep.Status.ReadyReplicas > 0 {
			log.Info("Deployment is ready")
			if err = r.Status().Update(ctx, cr); err != nil {
				log.Error(err, genericStatusUpdateFailedMessage)
				return ctrl.Result{}, err
			}

			return ctrl.Result{}, nil
		}

		// Wait up to 15 minutes for deployment to become ready
		if dep.CreationTimestamp.Add(15 * time.Minute).Before(time.Now()) {
			log.Info("Deployment still not ready, setting state to Error")
			cr.Status.State = typeError

			if err = r.Status().Update(ctx, cr); err != nil {
				log.Error(err, genericStatusUpdateFailedMessage)
				return ctrl.Result{}, err
			}
			return ctrl.Result{Requeue: true}, nil
		}

		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}

	if cr.Status.State == typeUpdating {
		log.Info("Updating: deleting previous deployment")

		// Delete deployment
		deployment := &appsv1.Deployment{}
		err = r.Get(ctx, types.NamespacedName{Name: formatResourceName(cr.Name), Namespace: cr.Namespace}, deployment)
		if err == nil {
			if err := r.Delete(ctx, deployment); err != nil {
				log.Error(err, "Failed to clean up deployment")
			}
		} else if !apierrors.IsNotFound(err) {
			log.Error(err, "Failed to get deployment")
			// Return error for reconciliation to be re-trigged
			return ctrl.Result{}, err
		}

		// Delete secret
		secret := &corev1.Secret{}
		err = r.Get(ctx, types.NamespacedName{Name: formatResourceName(cr.Name), Namespace: cr.Namespace}, secret)
		if !apierrors.IsNotFound(err) {
			log.Error(err, "Something went wrong while retrieving the secret to delete")
		}
		if err := r.Delete(ctx, secret); err != nil {
			log.Error(err, "Failed to clean up secret")
		}

		// Move to deploying state
		cr.Status.State = typeDeploying
		if err = r.Status().Update(ctx, cr); err != nil {
			log.Error(err, genericStatusUpdateFailedMessage)
			return ctrl.Result{}, err
		}

		return ctrl.Result{Requeue: true}, nil
	}

	if cr.Status.State == typeError {
		log.Info("Cleaning up secret, deployment and service")

		// Delete service
		service := &corev1.Service{}
		err = r.Get(ctx, types.NamespacedName{Name: formatResourceName(cr.Name), Namespace: cr.Namespace}, service)
		if err == nil {
			if err := r.Delete(ctx, service); err != nil {
				log.Error(err, "Failed to clean up service")
			}
		} else if !apierrors.IsNotFound(err) {
			log.Error(err, "Failed to get service")
			// Return error for reconciliation to be re-trigged
			return ctrl.Result{}, err
		}

		// Delete deployment
		deployment := &appsv1.Deployment{}
		err = r.Get(ctx, types.NamespacedName{Name: formatResourceName(cr.Name), Namespace: cr.Namespace}, deployment)
		if err == nil {
			if err := r.Delete(ctx, deployment); err != nil {
				log.Error(err, "Failed to clean up deployment")
			}
		} else if !apierrors.IsNotFound(err) {
			log.Error(err, "Failed to get deployment")
			// Return error for reconciliation to be re-trigged
			return ctrl.Result{}, err
		}

		// Delete secret
		secret := &corev1.Secret{}
		err = r.Get(ctx, types.NamespacedName{Name: formatResourceName(cr.Name), Namespace: cr.Namespace}, secret)
		if err == nil {
			if err := r.Delete(ctx, secret); err != nil {
				log.Error(err, "Failed to clean up secret")
			}
		} else if !apierrors.IsNotFound(err) {
			log.Error(err, "Failed to get secret")
			// Return error for reconciliation to be re-trigged
			return ctrl.Result{}, err
		}

		return ctrl.Result{}, nil
	}

	return ctrl.Result{}, nil
}

func handleMissingResource(r *DremioRestServerReconciler, ctx context.Context, cr *operatorv1.DremioRestServer, err error) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	if apierrors.IsNotFound(err) {
		cr.Status.State = typeDeploying
		if err = r.Status().Update(ctx, cr); err != nil {
			log.Error(err, genericStatusUpdateFailedMessage)
			return ctrl.Result{}, err
		}

		return ctrl.Result{Requeue: true}, nil
	}

	log.Error(err, "error while retrieving resource")
	return ctrl.Result{}, err
}

func crUpdated(dep *appsv1.Deployment, cr *operatorv1.DremioRestServer, newDremioUri string, oldDremioUri string) bool {
	if newDremioUri != oldDremioUri {
		return true
	}

	// Check if CR spec (JavaOptions, Tables) has been modified
	for _, env := range dep.Spec.Template.Spec.Containers[0].Env {
		if env.Name == "DREMIO_TABLES" {
			// Compare with current Tables
			if cr.Spec.Tables != env.Value {
				return true
			}
		}
	}

	return false
}

// deploymentForDremiorestserver returns a DremioRestServer Deployment object
func (r *DremioRestServerReconciler) deploymentForDremiorestserver(cr *operatorv1.DremioRestServer) (*appsv1.Deployment, error) {
	image, found := os.LookupEnv(dremioRestServerImage)
	if !found {
		image = "ghcr.io/scc-digitalhub/dremio-rest-server"
	}
	tag, found := os.LookupEnv(dremioRestServerImageTag)
	if !found {
		tag = "latest"
	}

	if cr.Spec.Tables == "" {
		return nil, errors.New("tables missing from spec")
	}

	ls := labelsForDremioRestServer(cr.Name, tag)
	selectors := selectorsForDremioRestServer(cr.Name)

	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      formatResourceName(cr.Name),
			Namespace: cr.Namespace,
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
							Limits:   getLimits(),
							Requests: getRequests(),
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
						},
						Env: []corev1.EnvVar{
							{
								Name: "DREMIO_URL",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{Name: formatResourceName(cr.Name)},
										Key:                  dremioUriSecretKey,
										Optional:             &[]bool{false}[0],
									},
								},
							},
							{
								Name:  "DREMIO_TABLES",
								Value: cr.Spec.Tables,
							},
						},
					}},
				},
			},
		},
	}

	// Set the ownerRef for the Deployment
	// More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/owners-dependents/
	if err := ctrl.SetControllerReference(cr, dep, r.Scheme); err != nil {
		return nil, err
	}
	return dep, nil
}

func (r *DremioRestServerReconciler) serviceForDremiorestserver(cr *operatorv1.DremioRestServer) (*corev1.Service, error) {
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

	ls := labelsForDremioRestServer(cr.Name, tag)
	selectors := selectorsForDremioRestServer(cr.Name)

	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      formatResourceName(cr.Name),
			Namespace: cr.Namespace,
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

	if err := ctrl.SetControllerReference(cr, service, r.Scheme); err != nil {
		return nil, err
	}

	return service, nil
}

func (r *DremioRestServerReconciler) createConnectionString(cr *operatorv1.DremioRestServer, ctx context.Context) (string, error) {
	host := cr.Spec.Connection.Host
	if host == "" {
		return "", fmt.Errorf("dremio host missing from spec")
	}

	user := cr.Spec.Connection.User
	password := cr.Spec.Connection.Password
	secretName := cr.Spec.Connection.SecretName

	// check that there is either password or secretName
	if secretName != "" {
		if password != "" || user != "" {
			return "", fmt.Errorf("either specify user and password or secretName")
		}

		//read secret
		secret := &corev1.Secret{}
		err := r.Get(ctx, types.NamespacedName{Name: secretName, Namespace: cr.Namespace}, secret)
		if err != nil {
			return "", err
		}

		//check that secret contains USER and PASSWORD
		userFromSecret := secret.Data["USER"]
		passwordFromSecret := secret.Data["PASSWORD"]
		if userFromSecret == nil || passwordFromSecret == nil {
			return "", fmt.Errorf("secret must contain USER and PASSWORD")
		}

		user = string(userFromSecret)
		password = string(passwordFromSecret)
	} else if password == "" || user == "" {
		return "", fmt.Errorf("specify both user and password")
	}

	port := cr.Spec.Connection.Port
	jdbcProperties := cr.Spec.Connection.JdbcProperties

	if port != 0 {
		host = fmt.Sprintf("%v:%v", host, port)
	}

	// build Dremio URI
	dremioRestServerUri := host

	str := []string{}
	if user != "" {
		str = append(str, fmt.Sprintf("user=%v", user))
	}
	if password != "" {
		str = append(str, fmt.Sprintf("password=%v", password))
	}
	if jdbcProperties != "" {
		str = append(str, jdbcProperties)
	}
	queryParams := strings.Join(str, "&")

	if queryParams != "" {
		dremioRestServerUri += fmt.Sprintf("?%v", queryParams)
	}

	return dremioRestServerUri, nil
}

func (r *DremioRestServerReconciler) secretForDremiorestserver(cr *operatorv1.DremioRestServer, ctx context.Context) (*corev1.Secret, error) {
	tag, found := os.LookupEnv(dremioRestServerImageTag)
	if !found {
		tag = "latest"
	}

	dremioRestServerUri, err := r.createConnectionString(cr, ctx)
	if err != nil {
		return nil, err
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      formatResourceName(cr.Name),
			Namespace: cr.Namespace,
			Labels:    labelsForDremioRestServer(cr.Name, tag),
		},
		StringData: map[string]string{dremioUriSecretKey: dremioRestServerUri},
	}

	if err := ctrl.SetControllerReference(cr, secret, r.Scheme); err != nil {
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
func (r *DremioRestServerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&operatorv1.DremioRestServer{}).
		Owns(&corev1.Secret{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Service{}).
		Complete(r)
}

func getLimits() corev1.ResourceList {
	limits := corev1.ResourceList{}

	limitsCpu, found := os.LookupEnv(containerLimitsCpu)
	if found {
		limits[corev1.ResourceCPU] = resource.MustParse(limitsCpu)
	}
	limitsMemory, found := os.LookupEnv(containerLimitsMemory)
	if found {
		limits[corev1.ResourceMemory] = resource.MustParse(limitsMemory)
	}

	return limits
}

func getRequests() corev1.ResourceList {
	requests := corev1.ResourceList{}

	requestsCpu, found := os.LookupEnv(containerRequestsCpu)
	if found {
		requests[corev1.ResourceCPU] = resource.MustParse(requestsCpu)
	}
	requestsMemory, found := os.LookupEnv(containerRequestsMemory)
	if found {
		requests[corev1.ResourceMemory] = resource.MustParse(requestsMemory)
	}

	return requests
}
