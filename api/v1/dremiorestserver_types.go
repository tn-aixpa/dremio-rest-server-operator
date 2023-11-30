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

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.
// Important: Run "make generate" after modifying this file

// Dremio REST Server properties
type DremioRestServerSpec struct {
	// Corresponds to JAVA_TOOL_OPTIONS: on JDK 9+, --add-opens=java.base/java.nio=ALL-UNNAMED is required
	// +operator-sdk:csv:customresourcedefinitions:type=spec
	JavaOptions string `json:"javaOptions,omitempty"` // JAVA_TOOL_OPTIONS

	// Comma-separated list of tables to expose
	// +operator-sdk:csv:customresourcedefinitions:type=spec
	Tables string `json:"tables,omitempty"` // DREMIO_TABLES (comma-separated)

	// Properties to connect to Dremio
	// +operator-sdk:csv:customresourcedefinitions:type=spec
	Dremio DremioProperties `json:"dremio,omitempty"`

	// Corresponds to resources.limits of a container
	// +operator-sdk:csv:customresourcedefinitions:type=spec
	ContainerLimits Limits `json:"containerLimits,omitempty"`

	// Corresponds to resources.requests of a container
	// +operator-sdk:csv:customresourcedefinitions:type=spec
	ContainerRequests Requests `json:"containerRequests,omitempty"`
}

type DremioProperties struct {
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	User     string `json:"user,omitempty"`
	Password string `json:"password,omitempty"`
	// Additional JDBC options supported by the Arrow Flight SQL JDBC driver that will be passed as query parameters (e.g.: useEncryption=false&disableCertificateVerification=true)
	JdbcProperties string `json:"jdbcProperties,omitempty"`
}

type Limits struct {
	Cpu    string `json:"cpu,omitempty"`
	Memory string `json:"memory,omitempty"`
}

type Requests struct {
	Cpu    string `json:"cpu,omitempty"`
	Memory string `json:"memory,omitempty"`
}

// Dremio REST Server status
type DremioRestServerStatus struct {
	// +operator-sdk:csv:customresourcedefinitions:type=status
	State string `json:"state,omitempty" patchStrategy:"merge"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// Schema for the dremiorestservers API
type DremioRestServer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   DremioRestServerSpec   `json:"spec,omitempty"`
	Status DremioRestServerStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// List of DremioRestServer
type DremioRestServerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []DremioRestServer `json:"items"`
}

func init() {
	SchemeBuilder.Register(&DremioRestServer{}, &DremioRestServerList{})
}
