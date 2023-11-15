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

// DremioRestServerSpec defines the desired state of DremioRestServer
type DremioRestServerSpec struct {
	// JAVA_TOOL_OPTIONS (on JDK 9+, --add-opens=java.base/java.nio=ALL-UNNAMED is required)
	// +operator-sdk:csv:customresourcedefinitions:type=spec
	JavaOptions string `json:"javaOptions,omitempty"` // JAVA_TOOL_OPTIONS

	// +operator-sdk:csv:customresourcedefinitions:type=spec
	DremioURL string `json:"dremioUrl,omitempty"` // DREMIO_URL

	// +operator-sdk:csv:customresourcedefinitions:type=spec
	Tables string `json:"tables,omitempty"` // DREMIO_TABLES (comma-separated)
}

// DremioRestServerStatus defines the observed state of DremioRestServer
type DremioRestServerStatus struct {
	// +operator-sdk:csv:customresourcedefinitions:type=status
	State string `json:"state,omitempty" patchStrategy:"merge"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// DremioRestServer is the Schema for the dremiorestservers API
type DremioRestServer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   DremioRestServerSpec   `json:"spec,omitempty"`
	Status DremioRestServerStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// DremioRestServerList contains a list of DremioRestServer
type DremioRestServerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []DremioRestServer `json:"items"`
}

func init() {
	SchemeBuilder.Register(&DremioRestServer{}, &DremioRestServerList{})
}
