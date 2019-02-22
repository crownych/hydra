# JsonWebKeySetGeneratorRequest

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Alg** | **string** | The algorithm to be used for creating the key. Supports \&quot;RS256\&quot;, \&quot;ES512\&quot;, \&quot;HS512\&quot;, and \&quot;HS256\&quot; | [default to null]
**Kid** | **string** | The kid of the key to be created | [default to null]
**Use** | **string** | The \&quot;use\&quot; (public key use) parameter identifies the intended use of the public key. The \&quot;use\&quot; parameter is employed to indicate whether a public key is used for encrypting data or verifying the signature on data. Valid values are \&quot;enc\&quot; and \&quot;sig\&quot;. | [default to null]
**Nbf** | ***int64** | The `nbf` (not before) parameter is an integer timestamp, measured in the number of seconds since January 1 1970 UTC, indicating when this key is not to be used before | [default to null]
**Exp** | ***int64** | The `exp` (expires at) parameter is an integer timestamp, measured in the number of seconds since January 1 1970 UTC, indicating when this key will expire | [default to null]

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


