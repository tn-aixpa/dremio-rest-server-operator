// Copyright 2023.
// SPDX-FileCopyrightText: © 2025 DSLab - Fondazione Bruno Kessler
//
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.
// Important: Run "make generate" after modifying this file

// Dremio REST Server properties
type DremioRestServerSpec struct {
	// Comma-separated list of tables to expose
	// +operator-sdk:csv:customresourcedefinitions:type=spec
	Tables string `json:"tables,omitempty"` // DREMIO_TABLES (comma-separated)

	// Properties to connect to Dremio
	// +operator-sdk:csv:customresourcedefinitions:type=spec
	Connection ConnectionProperties `json:"connection,omitempty"`
}

type ConnectionProperties struct {
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	User     string `json:"user,omitempty"`
	Password string `json:"password,omitempty"`
	// Additional JDBC options supported by the Arrow Flight SQL JDBC driver that will be passed as query parameters (e.g.: useEncryption=false&disableCertificateVerification=true)
	JdbcProperties string `json:"jdbcProperties,omitempty"`
	// Alternative to user and password properties; secret will have to contain USER and PASSWORD
	SecretName string `json:"secretName,omitempty"`
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
