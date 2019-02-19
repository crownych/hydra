# \JsonWebKeyApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**CommitJsonWebKeySet**](JsonWebKeyApi.md#CommitJsonWebKeySet) | **Put** /keys/commit | Commit a JSON Web Key Set
[**DeleteJsonWebKey**](JsonWebKeyApi.md#DeleteJsonWebKey) | **Delete** /keys/{set}/{kid} | Delete a JSON Web Key
[**DeleteJsonWebKeySet**](JsonWebKeyApi.md#DeleteJsonWebKeySet) | **Delete** /keys/{set} | Delete a JSON Web Key Set
[**GetJsonWebKey**](JsonWebKeyApi.md#GetJsonWebKey) | **Get** /keys/{set}/{kid} | Retrieve a JSON Web Key
[**GetJsonWebKeySet**](JsonWebKeyApi.md#GetJsonWebKeySet) | **Get** /keys/{set} | Retrieve a JSON Web Key Set
[**PutJsonWebKeySet**](JsonWebKeyApi.md#PutJsonWebKeySet) | **Put** /keys | Create or update a JSON Web Key Set

# **CommitJsonWebKeySet**
> CommitJsonWebKeySet($cookies, $commitCode)

Commit a JSON Web Key Set

Use this endpoint to commit a JSON Web Key Set.


### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **cookies** | **map[string]string** |  |
 **commitCode** | **string** | Token to commit the OAuth 2.0 confidential client | 

### Return type

[**CommitKeysResponse**](CommitKeysResponse.md)

### Authorization

AD Credentials required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **DeleteJsonWebKeySet**
> DeleteJsonWebKeySet($set)

Delete a JSON Web Key Set

Use this endpoint to delete a complete JSON Web Key Set and all the keys in that set.  A JSON Web Key (JWK) is a JavaScript Object Notation (JSON) data structure that represents a cryptographic key. A JWK Set is a JSON data structure that represents a set of JWKs. A JSON Web Key is identified by its set and key id. ORY Hydra uses this functionality to store cryptographic keys used for TLS and JSON Web Tokens (such as OpenID Connect ID tokens), and allows storing user-defined keys as well.


### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **set** | **string**| The set | 

### Return type

void (empty response body)

### Authorization

AD Credentials required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **GetJsonWebKey**
> JsonWebKeySet GetJsonWebKey($kid, $set)

Retrieve a JSON Web Key

This endpoint can be used to retrieve JWKs stored in ORY Hydra.  A JSON Web Key (JWK) is a JavaScript Object Notation (JSON) data structure that represents a cryptographic key. A JWK Set is a JSON data structure that represents a set of JWKs. A JSON Web Key is identified by its set and key id. ORY Hydra uses this functionality to store cryptographic keys used for TLS and JSON Web Tokens (such as OpenID Connect ID tokens), and allows storing user-defined keys as well.


### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **kid** | **string**| The kid of the desired key | 
 **set** | **string**| The set | 

### Return type

[**JsonWebKeySet**](JSONWebKeySet.md)

### Authorization

AD Credentials required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **GetJsonWebKeySet**
> JsonWebKeySet GetJsonWebKeySet($set)

Retrieve a JSON Web Key Set

This endpoint can be used to retrieve JWK Sets stored in ORY Hydra.  A JSON Web Key (JWK) is a JavaScript Object Notation (JSON) data structure that represents a cryptographic key. A JWK Set is a JSON data structure that represents a set of JWKs. A JSON Web Key is identified by its set and key id. ORY Hydra uses this functionality to store cryptographic keys used for TLS and JSON Web Tokens (such as OpenID Connect ID tokens), and allows storing user-defined keys as well.


### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **set** | **string**| The set | 

### Return type

[**JsonWebKeySet**](JSONWebKeySet.md)

### Authorization

AD Credentials required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **PutJsonWebKeySet**
> PutKeysResponse PutJsonWebKeySet($set, $body)

Create or update an OAuth 2.0 resource.

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **set** | string | JSON Web Key Set ID |
 **body** | [**JsonWebKeySet**](JsonWebKeySet.md)|  |
 
### Return type

[**PutKeysResponse**](PutKeysResponse.md)

### Authorization

AD user credentials required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

