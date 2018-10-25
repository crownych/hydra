# WellKnown

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Issuer** | **string** | URL using the https scheme with no query or fragment component that the OP asserts as its IssuerURL Identifier. If IssuerURL discovery is supported , this value MUST be identical to the issuer value returned by WebFinger. This also MUST be identical to the iss Claim value in ID Tokens issued from this IssuerURL. | [default to null]
**JwksUri** | **string** | URL of the OP&#39;s JSON Web Key Set [JWK] document. This contains the signing key(s) the RP uses to validate signatures from the OP. The JWK Set MAY also contain the Server&#39;s encryption key(s), which are used by RPs to encrypt requests to the Server. When both signing and encryption keys are made available, a use (Key Use) parameter value is REQUIRED for all keys in the referenced JWK Set to indicate each key&#39;s intended usage. Although some algorithms allow the same key to be used for both signatures and encryption, doing so is NOT RECOMMENDED, as it is less secure. The JWK x5c parameter MAY be used to provide X.509 representations of keys provided. When used, the bare key values MUST still be present and MUST match those in the certificate. | [default to null]
**ServiceDocumentation** | **string** | URL of the Service Documentation. | [default to null]
**AuthorizationEndpoint** | **string** | URL of the OP&#39;s OAuth 2.0 Authorization Endpoint. | [default to null]
**TokenEndpoint** | **string** | URL of the OP&#39;s OAuth 2.0 Token Endpoint | [default to null]
**RegistrationEndpoint** | **string** | URL of the OP&#39;s Dynamic Client Registration Endpoint. | [optional] [default to null]
**RevocationEndpoint** | **string** | URL of the OP&#39;s Token Revocation Endpoint. | [optional] [default to null]
**CheckSessionIframe** | **string** | OP iframe URL，用於通知 RP 登入狀態 | [optional] [default to null]
**EndSessionEndpoint** | **string** | Ends the session associated with the given ID token. | [optional] [default to null]
**ScopesSupported** | **[]string** | SON array containing a list of the OAuth 2.0 [RFC6749] scope values that this server supports. The server MUST support the openid scope value. Servers MAY choose not to advertise some supported scope values even when this parameter is used | [optional] [default to null]
**ResponseTypesSupported** | **[]string** | JSON array containing a list of the OAuth 2.0 response_type values that this OP supports. | [default to null]
**GrantTypesSupported** | **[]string** | JSON array containing a list of the OAuth 2.0 Grant Type values that this OP supports. | [optional] [default to null]
**TokenEndpointAuthMethodsSupported** | **[]string** | JSON array containing a list of Client Authentication methods supported by this Token Endpoint. | [optional] [default to null]
**TokenEndpointAuthSigningAlgValuesSupported** | **[]string** | JSON array containing a list of the JWS signing algorithms (alg values) supported. | [default to null]
**RevocationEndpointAuthMethodsSupported** | **[]string** | JSON array containing a list of auth methods supported by the revocation endpoint. | [optional] [default to null]
**RevocationEndpointAuthSigningAlgValuesSupported** | **[]string** | JSON array containing a list of the JWS signing algorithms (alg values) supported. | [default to null]
**RequestParameterSupported** | **bool** | Boolean value specifying whether the OP supports use of the request parameter, with true indicating support. | [optional] [default to null]
**RequestObjectSigningAlgValuesSupported** | **[]string** | JSON array containing a list of the JWS signing algorithms (alg values) supported by the auth service for the request object to encode the Claims in a JWT. | [default to null]

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


