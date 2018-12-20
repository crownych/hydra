package swagger

import "fmt"

const (
	ResourceUrnPrefix = "urn:104v3:resource:"
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

	// AuthService is the URI of the authorization server responsible for the resource
	AuthService string `json:"auth_server,omitempty"`

	// List of paths provided by the resource
	Paths []Path `json:"paths" validate:"required,min=1"`

	// List of scopes supported by the resource
	Scopes []Scope `json:"scopes,omitempty"`

	// List of grant types that allow access to the resource
	GrantTypes []string `json:"grant_types" validate:"required,min=1,max=1"`

	// Resource version, in the format major_number.minor_number
	Version string `json:"version" validate:"required"`

	// List of contacts responsible for the resource
	Contacts []string `json:"contacts" validate:"required,min=1"`

	// Auth type of the scope in the resource level
	ScopeAuthType string `json:"scope_auth_type" validate:"required,oneof=none client user company"`

	// Description of the resource
	Description string `json:"description" validate:"required"`
}

func (r *OAuth2Resource) GetUrn() string {
	return fmt.Sprintf("%s%s:v%s", ResourceUrnPrefix, r.Name, r.Version)
}

// Resource represents an OAuth 2.0 Resource Path.
//
// swagger:model path
type Path struct {
	// URI path of the resource.
	Name string `json:"name"`

	// List of HTTP methods supported by the resource.
	Methods []Method `json:"methods"`

	// Description of the Path
	Description string `json:"description,omitempty"`
}

// Resource represents an OAuth 2.0 Resource Path Method.
//
// swagger:model method
type Method struct {
	// HTTP method name.
	Name string `json:"name"`

	// Scopes supported by the Path
	Scopes []string `json:"scopes,omitempty"`

	// Description of the method
	Description string `json:"description,omitempty"`
}

// Resource represents an OAuth 2.0 Resource Scope.
//
// swagger:model scope
type Scope struct {
	// Name of the scope.
	Name string `json:"name"`

	// Auth type of the scope
	AuthType string `json:"scope_auth_type,omitempty"`

	// Description of the scope
	Description string `json:"description,omitempty"`
}
