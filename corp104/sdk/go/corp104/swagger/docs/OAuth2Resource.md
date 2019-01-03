# OAuth2Resource

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Urn** | **string** | Unique name of the resource. | [default to null]
**Uri** | **string** | Base URI of the resource.    | [default to null]
**Name** | **string** | Name of the resource. | [default to null]
**Type** | **string** | Type of the resource. | [default to null]
**AuthService** | **string** | AuthService is the URI of the authorization server responsible for the resource. | [optional] [default to null]
**Paths** | [**[]OAuth2ResourcePath**](#oauth2resourcepath) | List of paths provided by the resource. | Required when type is `rest`. [default to null]
**GraphQLOperations** | [**[]GraphQLOperation**](#graphqloperation) | List of GraphQL operations provided by the resource. | Required when type is `graphql`. [default to null]
**Scopes** | [**[]OAuth2ResourceScope**](#oauth2resourcescope) | List of scopes supported by the resource. | [default to null]
**GrantTypes** | **[]string** | List of grant types that allow access to the resource. | [default to null]
**Contacts** | **[]string** | List of contacts responsible for the resource. | [default to null]
**DefaultScope** | **string** | Default scope of the resource. | [default to null]
**DefaultScopeAuthType** | **string** | Auth type of the default scope. | [default to null]
**Description** | **string** | Description of the resource. | [default to null]

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

# OAuth2ResourcePath

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Name** | **string** | URI path of the resource. | [default to null]
**Methods** | [**[]OAuth2ResourceMethod**](#oauth2resourcemethod) | List of HTTP methods supported by the resource. | [default to null]
**Description** | **string** | Description of the Path. | [default to null]

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

# OAuth2ResourceScope

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Name** | **string** | HTTP method name. | [default to null]
**ScopeAuthType** | **string** | Auth type of the scope. | [default to null]
**Description** | **string** | Description of the scope. | [default to null]

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

# OAuth2ResourceMethod

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Name** | **string** | HTTP method name. | [default to null]
**Scopes** | **[]string** | Scopes supported by the method. | [default to null]
**Description** | **string** | Description of the method. | [default to null]

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)

# GraphQLOperation

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Name** | **string** |Name of the GraphQL operation. | [default to null]
**Type** | **string** | Type of the GraphQL operation. | [default to null]
**Scopes** | **[]string** | Scopes supported by the GraphQL operation. | [default to null]
**Description** | **string** | Description of the GraphQL operation. | [default to null]

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
