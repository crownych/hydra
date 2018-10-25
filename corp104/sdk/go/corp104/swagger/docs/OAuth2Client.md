# OAuth2Client

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**ClientId** | **string** | ClientID  is the id for this client. | [default to null]
**ClientName** | **string** | Name is the human-readable string name of the client to be presented to the end-user during authorization. | [default to null]
**ClientUri** | **string** | ClientURI is an URL string of a web page providing information about the client. | [default to null]
**Contacts** | **[]string** | Contacts is an array of strings representing ways to contact people responsible for this client, typically email addresses. | [default to null]
**GrantTypes** | **[]string** | GrantTypes is an array of grant types the client is allowed to use. | [default to null]
**IdTokenSignedResponseAlg** | **string** | JWS alg algorithm [JWA] REQUIRED for signing the ID Token issued to this Client. | [optional] [default to null]
**Jwks** | [**JsonWebKeySet**](JSONWebKeySet.md) |  | [default to null]
**RedirectUris** | **[]string** | RedirectURIs is an array of allowed redirect urls for the client, for example http://mydomain/oauth/callback . | [optional] [default to null]
**RequestObjectSigningAlg** | **string** | JWS [JWS] alg algorithm [JWA] that MUST be used for signing Request Objects sent to the OP. All Request Objects from this Client MUST be rejected, if not signed with this algorithm. | [optional] [default to null]
**ResoureSets** | **[]string** | ResoureSets is an array containing resource set identifiers. | [optional] [default to null]
**ResponseTypes** | **[]string** | ResponseTypes is an array of the OAuth 2.0 response type strings that the client can use at the authorization endpoint. | [optional] [default to null]
**SoftwareId** | **string** | A unique identifier string to identify the client software to be dynamically registered. | [default to null]
**SoftwareVersion** | **string** | A version identifier string for the client software identified by “software_id”. | [default to null]
**TokenEndpointAuthMethod** | **string** | Requested Client Authentication method for the Token Endpoint. The options are client_secret_post, client_secret_basic, private_key_jwt, and none. | [default to null]

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

