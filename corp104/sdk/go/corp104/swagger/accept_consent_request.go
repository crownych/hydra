/*
 * ORY Hydra - Cloud Native OAuth 2.0 and OpenID Connect Server
 *
 * Welcome to the ORY Hydra HTTP API documentation. You will find documentation for all HTTP APIs here. Keep in mind that this document reflects the latest branch, always. Support for versioned documentation is coming in the future.
 *
 * OpenAPI spec version: Latest
 * Contact: hi@ory.am
 * Generated by: https://github.com/swagger-api/swagger-codegen.git
 */

package swagger

type AcceptConsentRequest struct {

	// GrantScope sets the scope the user authorized the client to use. Should be a subset of `requested_scope`
	GrantScope []string `json:"grant_scope,omitempty"`

	// Remember, if set to true, tells ORY Hydra to remember this consent authorization and reuse it if the same client asks the same user for the same, or a subset of, scope.
	Remember bool `json:"remember,omitempty"`

	// RememberFor sets how long the consent authorization should be remembered for in seconds. If set to `0`, the authorization will be remembered indefinitely.
	RememberFor int64 `json:"remember_for,omitempty"`

	Session ConsentRequestSession `json:"session,omitempty"`
}
