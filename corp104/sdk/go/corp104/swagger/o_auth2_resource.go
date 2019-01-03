package swagger

import (
	"fmt"
	"strings"
)

const (
	UrnPrefix = "urn:104:v3:resource:"

	RestResourceType = "rest"
	GraphQLResourceType = "graphql"
)

// Resource represents an OAuth 2.0 Resource.
//
// swagger:model resource
type OAuth2Resource struct {
	// Unique name of the resource.
	Urn string `json:"urn"`

	// Base URI of the resource.
	Uri string `json:"uri" validate:"required"`

	// Name of the resource.
	Name string `json:"name" validate:"required"`

	// Type of the resource.
	Type string `json:"type" validate:"required,oneof=rest graphql"`

	// AuthService is the URI of the authorization server responsible for the resource
	AuthService string `json:"auth_server,omitempty"`

	// List of paths provided by the resource
	Paths []OAuth2ResourcePath `json:"paths,omitempty" validate:"dive"`

	// List of GraphQL operations provided by the resource
	GraphQLOperations []GraphQLOperation `json:"graphql_operations,omitempty" validate:"dive"`

	// List of scopes supported by the resource
	Scopes []OAuth2ResourceScope `json:"scopes,omitempty" validate:"dive"`

	// List of grant types that allow access to the resource
	GrantTypes []string `json:"grant_types" validate:"required,min=1,dive,oneof=client_credentials implicit urn:ietf:params:oauth:grant-type:jwt-bearer"`

	// List of contacts responsible for the resource
	Contacts []string `json:"contacts" validate:"required,min=1"`

	// Default scope of the resource
	DefaultScope string `json:"default_scope"`

	// Auth type of the default scope
	DefaultScopeAuthType string `json:"default_scope_auth_type" validate:"required,oneof=none client user company"`

	// Description of the resource
	Description string `json:"description" validate:"required"`
}

func (r *OAuth2Resource) GetUrn() string {
	return fmt.Sprintf("%s%s:%s", UrnPrefix, r.Type, r.Name)
}

func (r *OAuth2Resource) GetDefaultScope() string {
	return strings.TrimPrefix(r.GetUrn(), UrnPrefix)
}

type OAuth2ResourcePath struct {
	// URI path of the resource.
	Name string `json:"name" validate:"required"`

	// List of HTTP methods supported by the resource.
	Methods []OAuth2ResourceMethod `json:"methods" validate:"required,min=1,dive"`

	// Description of the Path
	Description string `json:"description,omitempty"`
}

type OAuth2ResourceMethod struct {
	// HTTP method name.
	Name string `json:"name" validate:"required,oneof=CONNECT DELETE GET HEAD PATCH POST PUT OPTIONS TRACE"`

	// Scopes supported by the method
	Scopes []string `json:"scopes"`

	// Description of the method
	Description string `json:"description,omitempty"`
}

type OAuth2ResourceScope struct {
	// Name of the scope.
	Name string `json:"name" validate:"required`

	// Auth type of the scope
	ScopeAuthType string `json:"scope_auth_type"`

	// Description of the scope
	Description string `json:"description,omitempty"`
}

type GraphQLOperation struct {
	// Name of the scope.
	Name string `json:"name" validate:"required`

	// Type of the GraphQL operation.
	Type string `json:"type" validate:"required,oneof=query mutation subscription"`

	// Scopes supported by the GraphQL operation
	Scopes []string `json:"scopes"`

	// Description of the scope
	Description string `json:"description,omitempty"`
}
