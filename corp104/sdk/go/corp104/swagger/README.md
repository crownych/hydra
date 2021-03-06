# Go API client for swagger

Welcome to the ORY Hydra HTTP API documentation. You will find documentation for all HTTP APIs here. Keep in mind that this document reflects the latest branch, always. Support for versioned documentation is coming in the future.

## Overview
This API client was generated by the [swagger-codegen](https://github.com/swagger-api/swagger-codegen) project.  By using the [swagger-spec](https://github.com/swagger-api/swagger-spec) from a remote server, you can easily generate an API client.

- API version: Latest
- Package version: 1.0.0
- Build package: io.swagger.codegen.languages.GoClientCodegen
For more information, please visit [https://www.ory.sh](https://www.ory.sh)

## Installation
Put the package under your project folder and add the following in import:
```
    "./swagger"
```

## Documentation for API Endpoints

All URIs are relative to *http://localhost*

Class | Method | HTTP request | Description
------------ | ------------- | ------------- | -------------
*HealthApi* | [**IsInstanceAlive**](docs/HealthApi.md#isinstancealive) | **Get** /health/alive | Check the Alive Status
*HealthApi* | [**IsInstanceReady**](docs/HealthApi.md#isinstanceready) | **Get** /health/ready | Check the Readiness Status
*JsonWebKeyApi* | [**CommitJsonWebKeySet**](docs/JsonWebKeyApi.md#commitjsonwebkeyset) | **Put** /keys/commit | Commit a JSON Web Key Set
*JsonWebKeyApi* | [**DeleteJsonWebKey**](docs/JsonWebKeyApi.md#deletejsonwebkey) | **Delete** /keys/{set}/{kid} | Delete a JSON Web Key
*JsonWebKeyApi* | [**DeleteJsonWebKeySet**](docs/JsonWebKeyApi.md#deletejsonwebkeyset) | **Delete** /keys/{set} | Delete a JSON Web Key Set
*JsonWebKeyApi* | [**GetJsonWebKey**](docs/JsonWebKeyApi.md#getjsonwebkey) | **Get** /keys/{set}/{kid} | Retrieve a JSON Web Key
*JsonWebKeyApi* | [**GetJsonWebKeySet**](docs/JsonWebKeyApi.md#getjsonwebkeyset) | **Get** /keys/{set} | Retrieve a JSON Web Key Set
*JsonWebKeyApi* | [**PutJsonWebKeySet**](docs/JsonWebKeyApi.md#putjsonwebkeyset) | **Put** /keys | Create or update a JSON Web Key Set
*MetricsApi* | [**GetPrometheusMetrics**](docs/MetricsApi.md#getprometheusmetrics) | **Get** /metrics/prometheus | Retrieve Prometheus metrics
*OAuth2Api* | [**AcceptConsentRequest**](docs/OAuth2Api.md#acceptconsentrequest) | **Put** /oauth2/auth/requests/consent/{challenge}/accept | Accept an consent request
*OAuth2Api* | [**AcceptLoginRequest**](docs/OAuth2Api.md#acceptloginrequest) | **Put** /oauth2/auth/requests/login/{challenge}/accept | Accept an login request
*OAuth2Api* | [**CommitOAuth2Client**](docs/OAuth2Api.md#commitoauth2client) | **Put** /clients/commit | Commit an OAuth 2.0 confidential client
*OAuth2Api* | [**DeleteOAuth2Client**](docs/OAuth2Api.md#deleteoauth2client) | **Delete** /clients/{id} | Deletes an OAuth 2.0 Client
*OAuth2Api* | [**FlushInactiveOAuth2Tokens**](docs/OAuth2Api.md#flushinactiveoauth2tokens) | **Post** /oauth2/flush | Flush Expired OAuth2 Access Tokens
*OAuth2Api* | [**GetConsentRequest**](docs/OAuth2Api.md#getconsentrequest) | **Get** /oauth2/auth/requests/consent/{challenge} | Get consent request information
*OAuth2Api* | [**GetLoginRequest**](docs/OAuth2Api.md#getloginrequest) | **Get** /oauth2/auth/requests/login/{challenge} | Get an login request
*OAuth2Api* | [**GetOAuth2Client**](docs/OAuth2Api.md#getoauth2client) | **Get** /clients/{id} | Get an OAuth 2.0 Client.
*OAuth2Api* | [**GetOAuth2Token**](docs/OAuth2Api.md#getoauth2token) | **Post** /token | Get an OAuth 2.0 access token.
*OAuth2Api* | [**GetWellKnown**](docs/OAuth2Api.md#getwellknown) | **Get** /.well-known/oauth-authorization-server | Server well known configuration
*OAuth2Api* | [**IntrospectOAuth2Token**](docs/OAuth2Api.md#introspectoauth2token) | **Post** /oauth2/introspect | Introspect OAuth2 tokens
*OAuth2Api* | [**ListOAuth2Clients**](docs/OAuth2Api.md#listoauth2clients) | **Get** /clients | List OAuth 2.0 Clients
*OAuth2Api* | [**ListUserConsentSessions**](docs/OAuth2Api.md#listuserconsentsessions) | **Get** /oauth2/auth/sessions/consent/{user} | Lists all consent sessions of a user
*OAuth2Api* | [**OauthAuth**](docs/OAuth2Api.md#oauthauth) | **Get** /oauth2/auth | The OAuth 2.0 authorize endpoint
*OAuth2Api* | [**OauthToken**](docs/OAuth2Api.md#oauthtoken) | **Post** /token | The OAuth 2.0 token endpoint
*OAuth2Api* | [**PutOAuth2Client**](docs/OAuth2Api.md#putoauth2client) | **Put** /clients | Create or update an OAuth 2.0 client
*OAuth2Api* | [**RejectConsentRequest**](docs/OAuth2Api.md#rejectconsentrequest) | **Put** /oauth2/auth/requests/consent/{challenge}/reject | Reject an consent request
*OAuth2Api* | [**RejectLoginRequest**](docs/OAuth2Api.md#rejectloginrequest) | **Put** /oauth2/auth/requests/login/{challenge}/reject | Reject a login request
*OAuth2Api* | [**RevokeAllUserConsentSessions**](docs/OAuth2Api.md#revokealluserconsentsessions) | **Delete** /oauth2/auth/sessions/consent/{user} | Revokes all previous consent sessions of a user
*OAuth2Api* | [**RevokeAuthenticationSession**](docs/OAuth2Api.md#revokeauthenticationsession) | **Delete** /oauth2/auth/sessions/login/{user} | Invalidates a user&#39;s authentication session
*OAuth2Api* | [**RevokeOAuth2Token**](docs/OAuth2Api.md#revokeoauth2token) | **Post** /revoke | Revoke OAuth2 tokens
*OAuth2Api* | [**RevokeUserClientConsentSessions**](docs/OAuth2Api.md#revokeuserclientconsentsessions) | **Delete** /oauth2/auth/sessions/consent/{user}/{client} | Revokes consent sessions of a user for a specific OAuth 2.0 Client
*OAuth2Api* | [**RevokeUserLoginCookie**](docs/OAuth2Api.md#revokeuserlogincookie) | **Get** /oauth2/auth/sessions/login/revoke | Logs user out by deleting the session cookie
*OAuth2Api* | [**Userinfo**](docs/OAuth2Api.md#userinfo) | **Post** /userinfo | OpenID Connect Userinfo
*OAuth2Api* | [**WellKnown**](docs/OAuth2Api.md#wellknown) | **Get** /.well-known/jwks.json | Get Well-Known JSON Web Keys
*VersionApi* | [**GetVersion**](docs/VersionApi.md#getversion) | **Get** /version | Get the version of Hydra


## Documentation For Models

 - [AcceptConsentRequest](docs/AcceptConsentRequest.md)
 - [AcceptLoginRequest](docs/AcceptLoginRequest.md)
 - [AuthenticationSession](docs/AuthenticationSession.md)
 - [CommitClientResponse](docs/CommitClientResponse.md)
 - [CommitKeysResponse](docs/CommitKeysResponse.md)
 - [CommitResourceResponse](docs/CommitResourceResponse.md)
 - [CompletedRequest](docs/CompletedRequest.md)
 - [ConsentRequest](docs/ConsentRequest.md)
 - [ConsentRequestSession](docs/ConsentRequestSession.md)
 - [FlushInactiveOAuth2TokensRequest](docs/FlushInactiveOAuth2TokensRequest.md)
 - [HealthNotReadyStatus](docs/HealthNotReadyStatus.md)
 - [HealthStatus](docs/HealthStatus.md)
 - [InlineResponse401](docs/InlineResponse401.md)
 - [JoseWebKeySetRequest](docs/JoseWebKeySetRequest.md)
 - [JsonWebKey](docs/JsonWebKey.md)
 - [JsonWebKeySet](docs/JsonWebKeySet.md)
 - [JsonWebKeySetGeneratorRequest](docs/JsonWebKeySetGeneratorRequest.md)
 - [LoginRequest](docs/LoginRequest.md)
 - [OAuth2Client](docs/OAuth2Client.md)
 - [OAuth2TokenIntrospection](docs/OAuth2TokenIntrospection.md)
 - [OauthTokenResponse](docs/OauthTokenResponse.md)
 - [OpenIdConnectContext](docs/OpenIdConnectContext.md)
 - [PreviousConsentSession](docs/PreviousConsentSession.md)
 - [PutClientResponse](docs/PutClientResponse.md)
 - [PutKeysResponse](docs/PutKeysResponse.md)
 - [PutResourceResponse](docs/PutResourceResponse.md)
 - [RawMessage](docs/RawMessage.md)
 - [RejectRequest](docs/RejectRequest.md)
 - [SwaggerFlushInactiveAccessTokens](docs/SwaggerFlushInactiveAccessTokens.md)
 - [SwaggerJsonWebKeyQuery](docs/SwaggerJsonWebKeyQuery.md)
 - [SwaggerJwkCreateSet](docs/SwaggerJwkCreateSet.md)
 - [SwaggerJwkSetQuery](docs/SwaggerJwkSetQuery.md)
 - [SwaggerJwkUpdateSet](docs/SwaggerJwkUpdateSet.md)
 - [SwaggerJwkUpdateSetKey](docs/SwaggerJwkUpdateSetKey.md)
 - [SwaggerOAuthIntrospectionRequest](docs/SwaggerOAuthIntrospectionRequest.md)
 - [SwaggerRevokeOAuth2TokenParameters](docs/SwaggerRevokeOAuth2TokenParameters.md)
 - [UserinfoResponse](docs/UserinfoResponse.md)
 - [Version](docs/Version.md)
 - [WellKnown](docs/WellKnown.md)


## Documentation For Authorization


## basic

- **Type**: HTTP basic authentication

## oauth2

- **Type**: OAuth
- **Flow**: accessCode
- **Authorization URL**: https://your-hydra-instance.com/oauth2/auth
- **Scopes**: 
 - **offline**: A scope required when requesting refresh tokens
 - **openid**: Request an OpenID Connect ID Token


## Author

hi@ory.am

