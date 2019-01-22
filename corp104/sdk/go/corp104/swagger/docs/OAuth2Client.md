# OAuth2Client

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**AllowedCorsOrigins** | **[]string** | AllowedCORSOrigins are one or more URLs (scheme://host[:port]) which are allowed to make CORS requests to the /oauth/token endpoint. If this array is empty, the sever&#39;s CORS origin configuration (&#x60;CORS_ALLOWED_ORIGINS&#x60;) will be used instead. If this array is set, the allowed origins are appended to the server&#39;s CORS origin configuration. Be aware that environment variable &#x60;CORS_ENABLED&#x60; MUST be set to &#x60;true&#x60; for this to work. | [optional] [default to null]
**ClientId** | **string** | ClientID  is the id for this client. | [optional] [default to null]
**ClientName** | **string** | Name is the human-readable string name of the client to be presented to the end-user during authorization. | [optional] [default to null]
**ClientUri** | **string** | ClientURI is an URL string of a web page providing information about the client. | [default to null]
**Contacts** | **[]string** | Contacts is an array of strings representing ways to contact people responsible for this client, typically email addresses. | [optional] [default to null]
**GrantTypes** | **[]string** | GrantTypes is an array of grant types the client is allowed to use. | [optional] [default to null]
**IdTokenSignedResponseAlg** | **string** | JWS alg algorithm [JWA] REQUIRED for signing the ID Token issued to this Client. | [optional] [default to null]
**Jwks** | [**JsonWebKeySet**](JSONWebKeySet.md) |  | [default to null]
**LogoUri** | **string** | LogoURI is an URL string that references a logo for the client. | [optional] [default to null]
**Owner** | **string** | Owner is a string identifying the owner of the OAuth 2.0 Client. | [optional] [default to null]
**PolicyUri** | **string** | PolicyURI is a URL string that points to a human-readable privacy policy document that describes how the deployment organization collects, uses, retains, and discloses personal data. | [optional] [default to null]
**RedirectUris** | **[]string** | RedirectURIs is an array of allowed redirect urls for the client, for example http://mydomain/oauth/callback . | [optional] [default to null]
**RequestObjectSigningAlg** | **string** | JWS [JWS] alg algorithm [JWA] that MUST be used for signing Request Objects sent to the OP. All Request Objects from this Client MUST be rejected, if not signed with this algorithm. | [optional] [default to null]
**RequestUris** | **[]string** | Array of request_uri values that are pre-registered by the RP for use at the OP. Servers MAY cache the contents of the files referenced by these URIs and not retrieve them at the time they are used in a request. OPs can require that request_uri values used be pre-registered with the require_request_uri_registration discovery parameter. | [optional] [default to null]
**ResponseTypes** | **[]string** | ResponseTypes is an array of the OAuth 2.0 response type strings that the client can use at the authorization endpoint. | [optional] [default to null]
**Scope** | **string** | Scope is a string containing a space-separated list of scope values (as described in Section 3.3 of OAuth 2.0 [RFC6749]) that the client can use when requesting access tokens. | [optional] [default to null]
**SectorIdentifierUri** | **string** | URL using the https scheme to be used in calculating Pseudonymous Identifiers by the OP. The URL references a file with a single JSON array of redirect_uri values. | [optional] [default to null]
**SubjectType** | **string** | SubjectType requested for responses to this Client. The subject_types_supported Discovery parameter contains a list of the supported subject_type values for this server. Valid types include &#x60;pairwise&#x60; and &#x60;public&#x60;. | [optional] [default to null]
**SoftwareId** | **string** | A unique identifier string to identify the client software to be dynamically registered. | [optional] [default to null]
**SoftwareVersion** | **string** | A version identifier string for the client software identified by “software_id”. | [optional] [default to null]
**TokenEndpointAuthMethod** | **string** | Requested Client Authentication method for the Token Endpoint. The options are client_secret_post, client_secret_basic, private_key_jwt, and none. | [optional] [default to null]
**TosUri** | **string** | TermsOfServiceURI is a URL string that points to a human-readable terms of service document for the client that describes a contractual relationship between the end-user and the client that the end-user accepts when authorizing the client. | [optional] [default to null]
**UserinfoSignedResponseAlg** | **string** | JWS alg algorithm [JWA] REQUIRED for signing UserInfo Responses. If this is specified, the response will be JWT [JWT] serialized, and signed using JWS. The default, if omitted, is for the UserInfo Response to return the Claims as a UTF-8 encoded JSON object using the application/json content-type. | [optional] [default to null]
**ClientProfile** | **string** | Client Profile. Supported public client profiles are `user-agent-based` & `native`; Supported confidential client profiles are `web` & `batch`.  | [default to null]

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

