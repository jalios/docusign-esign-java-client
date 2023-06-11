package com.docusign.esign.api;

import com.docusign.esign.client.ApiClient;
import com.docusign.esign.client.ApiException;
import com.docusign.esign.client.ApiResponse;
import com.docusign.esign.client.Configuration;
import com.docusign.esign.client.Pair;
import com.docusign.esign.model.*;
import com.docusign.esign.override.jarkarta.GenericType;

/** AuthenticationApi class. */
public class AuthenticationApi {
  private ApiClient apiClient;

  /** AuthenticationApi. */
  public AuthenticationApi() {
    this(Configuration.getDefaultApiClient());
  }

  /** AuthenticationApi. */
  public AuthenticationApi(ApiClient apiClient) {
    this.apiClient = apiClient;
  }

  /**
   * getApiClient Method.
   *
   * @return ApiClient
   */
  public ApiClient getApiClient() {
    return apiClient;
  }

  /** setApiClient Method. */
  public void setApiClient(ApiClient apiClient) {
    this.apiClient = apiClient;
  }

  /**
   * Deletes user&#39;s social account.. Deletes a social account from a use&#39;s account.
   *
   * @param accountId The external account number (int) or account ID Guid. (required)
   * @param userId The user ID of the user being accessed. Generally this is the user ID of the
   *     authenticated user, but if the authenticated user is an Admin on the account, this may be
   *     another user the Admin user is accessing. (required)
   * @param socialAccountInformation (optional)
   * @throws ApiException if fails to make API call
   */
  public void deleteSocialLogin(
      String accountId, String userId, SocialAccountInformation socialAccountInformation)
      throws ApiException {
    deleteSocialLoginWithHttpInfo(accountId, userId, socialAccountInformation);
  }

  /**
   * Deletes user&#39;s social account. Deletes a social account from a use&#39;s account.
   *
   * @param accountId The external account number (int) or account ID Guid. (required)
   * @param userId The user ID of the user being accessed. Generally this is the user ID of the
   *     authenticated user, but if the authenticated user is an Admin on the account, this may be
   *     another user the Admin user is accessing. (required)
   * @param socialAccountInformation (optional)
   * @throws ApiException if fails to make API call
   */
  public ApiResponse<Object> deleteSocialLoginWithHttpInfo(
      String accountId, String userId, SocialAccountInformation socialAccountInformation)
      throws ApiException {
    Object localVarPostBody = socialAccountInformation;

    // verify the required parameter 'accountId' is set
    if (accountId == null) {
      throw new ApiException(
          400, "Missing the required parameter 'accountId' when calling deleteSocialLogin");
    }

    // verify the required parameter 'userId' is set
    if (userId == null) {
      throw new ApiException(
          400, "Missing the required parameter 'userId' when calling deleteSocialLogin");
    }

    // create path and map variables
    String localVarPath =
        "/v2.1/accounts/{accountId}/users/{userId}/social"
            .replaceAll("\\{" + "accountId" + "\\}", apiClient.escapeString(accountId.toString()))
            .replaceAll("\\{" + "userId" + "\\}", apiClient.escapeString(userId.toString()));

    // query params
    java.util.List<Pair> localVarQueryParams = new java.util.ArrayList<Pair>();
    java.util.List<Pair> localVarCollectionQueryParams = new java.util.ArrayList<Pair>();
    java.util.Map<String, String> localVarHeaderParams = new java.util.HashMap<String, String>();
    java.util.Map<String, Object> localVarFormParams = new java.util.HashMap<String, Object>();

    final String[] localVarAccepts = {"application/json"};
    final String localVarAccept = apiClient.selectHeaderAccept(localVarAccepts);

    final String[] localVarContentTypes = {};

    final String localVarContentType = apiClient.selectHeaderContentType(localVarContentTypes);

    String[] localVarAuthNames = new String[] {"docusignAccessCode"};

    apiClient.invokeAPI(
        localVarPath,
        "DELETE",
        localVarQueryParams,
        localVarCollectionQueryParams,
        localVarPostBody,
        localVarHeaderParams,
        localVarFormParams,
        localVarAccept,
        localVarContentType,
        localVarAuthNames,
        null);
    return new ApiResponse<Object>(apiClient.getStatusCode(), apiClient.getResponseHeaders(), null);
  }

  /**
   * Creates an authorization token.. Creates an OAuth2 authorization server token endpoint.
   *
   * @return OauthAccess
   * @throws ApiException if fails to make API call
   */
  public OauthAccess getOAuthToken() throws ApiException {
    ApiResponse<OauthAccess> localVarResponse = getOAuthTokenWithHttpInfo();
    return localVarResponse.getData();
  }

  /**
   * Creates an authorization token. Creates an OAuth2 authorization server token endpoint.
   *
   * @return OauthAccess
   * @throws ApiException if fails to make API call
   */
  public ApiResponse<OauthAccess> getOAuthTokenWithHttpInfo() throws ApiException {
    Object localVarPostBody = "{}";

    // create path and map variables
    String localVarPath = "/v2.1/oauth2/token";

    // query params
    java.util.List<Pair> localVarQueryParams = new java.util.ArrayList<Pair>();
    java.util.List<Pair> localVarCollectionQueryParams = new java.util.ArrayList<Pair>();
    java.util.Map<String, String> localVarHeaderParams = new java.util.HashMap<String, String>();
    java.util.Map<String, Object> localVarFormParams = new java.util.HashMap<String, Object>();

    final String[] localVarAccepts = {"application/json"};
    final String localVarAccept = apiClient.selectHeaderAccept(localVarAccepts);

    final String[] localVarContentTypes = {};

    final String localVarContentType = apiClient.selectHeaderContentType(localVarContentTypes);

    String[] localVarAuthNames = new String[] {"docusignAccessCode"};

    GenericType<OauthAccess> localVarReturnType = new GenericType<OauthAccess>() {};
    OauthAccess localVarResponse =
        apiClient.invokeAPI(
            localVarPath,
            "POST",
            localVarQueryParams,
            localVarCollectionQueryParams,
            localVarPostBody,
            localVarHeaderParams,
            localVarFormParams,
            localVarAccept,
            localVarContentType,
            localVarAuthNames,
            localVarReturnType);
    return new ApiResponse<OauthAccess>(
        apiClient.getStatusCode(), apiClient.getResponseHeaders(), localVarResponse);
  }

  /**
   * Gets a list of a user&#39;s social accounts.. Retrieves a list of social accounts linked to a
   * user&#39;s account.
   *
   * @param accountId The external account number (int) or account ID Guid. (required)
   * @param userId The user ID of the user being accessed. Generally this is the user ID of the
   *     authenticated user, but if the authenticated user is an Admin on the account, this may be
   *     another user the Admin user is accessing. (required)
   * @return UserSocialIdResult
   * @throws ApiException if fails to make API call
   */
  public UserSocialIdResult listSocialLogins(String accountId, String userId) throws ApiException {
    ApiResponse<UserSocialIdResult> localVarResponse =
        listSocialLoginsWithHttpInfo(accountId, userId);
    return localVarResponse.getData();
  }

  /**
   * Gets a list of a user&#39;s social accounts. Retrieves a list of social accounts linked to a
   * user&#39;s account.
   *
   * @param accountId The external account number (int) or account ID Guid. (required)
   * @param userId The user ID of the user being accessed. Generally this is the user ID of the
   *     authenticated user, but if the authenticated user is an Admin on the account, this may be
   *     another user the Admin user is accessing. (required)
   * @return UserSocialIdResult
   * @throws ApiException if fails to make API call
   */
  public ApiResponse<UserSocialIdResult> listSocialLoginsWithHttpInfo(
      String accountId, String userId) throws ApiException {
    Object localVarPostBody = "{}";

    // verify the required parameter 'accountId' is set
    if (accountId == null) {
      throw new ApiException(
          400, "Missing the required parameter 'accountId' when calling listSocialLogins");
    }

    // verify the required parameter 'userId' is set
    if (userId == null) {
      throw new ApiException(
          400, "Missing the required parameter 'userId' when calling listSocialLogins");
    }

    // create path and map variables
    String localVarPath =
        "/v2.1/accounts/{accountId}/users/{userId}/social"
            .replaceAll("\\{" + "accountId" + "\\}", apiClient.escapeString(accountId.toString()))
            .replaceAll("\\{" + "userId" + "\\}", apiClient.escapeString(userId.toString()));

    // query params
    java.util.List<Pair> localVarQueryParams = new java.util.ArrayList<Pair>();
    java.util.List<Pair> localVarCollectionQueryParams = new java.util.ArrayList<Pair>();
    java.util.Map<String, String> localVarHeaderParams = new java.util.HashMap<String, String>();
    java.util.Map<String, Object> localVarFormParams = new java.util.HashMap<String, Object>();

    final String[] localVarAccepts = {"application/json"};
    final String localVarAccept = apiClient.selectHeaderAccept(localVarAccepts);

    final String[] localVarContentTypes = {};

    final String localVarContentType = apiClient.selectHeaderContentType(localVarContentTypes);

    String[] localVarAuthNames = new String[] {"docusignAccessCode"};

    GenericType<UserSocialIdResult> localVarReturnType = new GenericType<UserSocialIdResult>() {};
    UserSocialIdResult localVarResponse =
        apiClient.invokeAPI(
            localVarPath,
            "GET",
            localVarQueryParams,
            localVarCollectionQueryParams,
            localVarPostBody,
            localVarHeaderParams,
            localVarFormParams,
            localVarAccept,
            localVarContentType,
            localVarAuthNames,
            localVarReturnType);
    return new ApiResponse<UserSocialIdResult>(
        apiClient.getStatusCode(), apiClient.getResponseHeaders(), localVarResponse);
  }
  /// <summary>
  /// Gets login information for a specified user. Retrieves login information for a specified user.
  // Each account that is associated with the login credentials is listed. You can use the returned
  // information to determine whether a user is authenticated and select an account to use in future
  // operations.    The &#x60;baseUrl&#x60; property, returned in the response, is used in all
  // future API calls as the base of the request URL. The &#x60;baseUrl&#x60; property contains the
  // DocuSign server, the API version, and the &#x60;accountId&#x60; property that is used for the
  // login. This request uses your DocuSign credentials to retrieve the account information.
  /// </summary>

  /** LoginOptions Class. */
  public class LoginOptions {
    private String apiPassword = null;
    private String embedAccountIdGuid = null;
    private String includeAccountIdGuid = null;
    private String loginSettings = null;

    /** setApiPassword method. */
    public void setApiPassword(String apiPassword) {
      this.apiPassword = apiPassword;
    }

    /**
     * getApiPassword method.
     *
     * @return String
     */
    public String getApiPassword() {
      return this.apiPassword;
    }

    /** setEmbedAccountIdGuid method. */
    public void setEmbedAccountIdGuid(String embedAccountIdGuid) {
      this.embedAccountIdGuid = embedAccountIdGuid;
    }

    /**
     * getEmbedAccountIdGuid method.
     *
     * @return String
     */
    public String getEmbedAccountIdGuid() {
      return this.embedAccountIdGuid;
    }

    /** setIncludeAccountIdGuid method. */
    public void setIncludeAccountIdGuid(String includeAccountIdGuid) {
      this.includeAccountIdGuid = includeAccountIdGuid;
    }

    /**
     * getIncludeAccountIdGuid method.
     *
     * @return String
     */
    public String getIncludeAccountIdGuid() {
      return this.includeAccountIdGuid;
    }

    /** setLoginSettings method. */
    public void setLoginSettings(String loginSettings) {
      this.loginSettings = loginSettings;
    }

    /**
     * getLoginSettings method.
     *
     * @return String
     */
    public String getLoginSettings() {
      return this.loginSettings;
    }
  }

  /**
   * Gets login information for a specified user.. Retrieves login information for a specified user.
   * Each account that is associated with the login credentials is listed. You can use the returned
   * information to determine whether a user is authenticated and select an account to use in future
   * operations. The &#x60;baseUrl&#x60; property, returned in the response, is used in all future
   * API calls as the base of the request URL. The &#x60;baseUrl&#x60; property contains the
   * DocuSign server, the API version, and the &#x60;accountId&#x60; property that is used for the
   * login. This request uses your DocuSign credentials to retrieve the account information.
   *
   * @return LoginInformation
   */
  public LoginInformation login() throws ApiException {
    return login(null);
  }

  /**
   * Gets login information for a specified user.. Retrieves login information for a specified user.
   * Each account that is associated with the login credentials is listed. You can use the returned
   * information to determine whether a user is authenticated and select an account to use in future
   * operations. The &#x60;baseUrl&#x60; property, returned in the response, is used in all future
   * API calls as the base of the request URL. The &#x60;baseUrl&#x60; property contains the
   * DocuSign server, the API version, and the &#x60;accountId&#x60; property that is used for the
   * login. This request uses your DocuSign credentials to retrieve the account information.
   *
   * @param options for modifying the method behavior.
   * @return LoginInformation
   * @throws ApiException if fails to make API call
   */
  public LoginInformation login(AuthenticationApi.LoginOptions options) throws ApiException {
    ApiResponse<LoginInformation> localVarResponse = loginWithHttpInfo(options);
    return localVarResponse.getData();
  }

  /**
   * Gets login information for a specified user. Retrieves login information for a specified user.
   * Each account that is associated with the login credentials is listed. You can use the returned
   * information to determine whether a user is authenticated and select an account to use in future
   * operations. The &#x60;baseUrl&#x60; property, returned in the response, is used in all future
   * API calls as the base of the request URL. The &#x60;baseUrl&#x60; property contains the
   * DocuSign server, the API version, and the &#x60;accountId&#x60; property that is used for the
   * login. This request uses your DocuSign credentials to retrieve the account information.
   *
   * @param options for modifying the method behavior.
   * @return LoginInformation
   * @throws ApiException if fails to make API call
   */
  public ApiResponse<LoginInformation> loginWithHttpInfo(AuthenticationApi.LoginOptions options)
      throws ApiException {
    Object localVarPostBody = "{}";

    // create path and map variables
    String localVarPath = "/v2.1/login_information";

    // query params
    java.util.List<Pair> localVarQueryParams = new java.util.ArrayList<Pair>();
    java.util.List<Pair> localVarCollectionQueryParams = new java.util.ArrayList<Pair>();
    java.util.Map<String, String> localVarHeaderParams = new java.util.HashMap<String, String>();
    java.util.Map<String, Object> localVarFormParams = new java.util.HashMap<String, Object>();

    if (options != null) {
      localVarQueryParams.addAll(apiClient.parameterToPair("api_password", options.apiPassword));
    }
    if (options != null) {
      localVarQueryParams.addAll(
          apiClient.parameterToPair("embed_account_id_guid", options.embedAccountIdGuid));
    }
    if (options != null) {
      localVarQueryParams.addAll(
          apiClient.parameterToPair("include_account_id_guid", options.includeAccountIdGuid));
    }
    if (options != null) {
      localVarQueryParams.addAll(
          apiClient.parameterToPair("login_settings", options.loginSettings));
    }

    final String[] localVarAccepts = {"application/json"};
    final String localVarAccept = apiClient.selectHeaderAccept(localVarAccepts);

    final String[] localVarContentTypes = {};

    final String localVarContentType = apiClient.selectHeaderContentType(localVarContentTypes);

    String[] localVarAuthNames = new String[] {"docusignAccessCode"};

    GenericType<LoginInformation> localVarReturnType = new GenericType<LoginInformation>() {};
    LoginInformation localVarResponse =
        apiClient.invokeAPI(
            localVarPath,
            "GET",
            localVarQueryParams,
            localVarCollectionQueryParams,
            localVarPostBody,
            localVarHeaderParams,
            localVarFormParams,
            localVarAccept,
            localVarContentType,
            localVarAuthNames,
            localVarReturnType);
    return new ApiResponse<LoginInformation>(
        apiClient.getStatusCode(), apiClient.getResponseHeaders(), localVarResponse);
  }

  /**
   * Revokes an authorization token.. Revokes an OAuth2 authorization server token. After the
   * revocation is complete, a caller must re-authenticate to restore access.
   *
   * @throws ApiException if fails to make API call
   */
  public void revokeOAuthToken() throws ApiException {
    revokeOAuthTokenWithHttpInfo();
  }

  /**
   * Revokes an authorization token. Revokes an OAuth2 authorization server token. After the
   * revocation is complete, a caller must re-authenticate to restore access.
   *
   * @throws ApiException if fails to make API call
   */
  public ApiResponse<Object> revokeOAuthTokenWithHttpInfo() throws ApiException {
    Object localVarPostBody = "{}";

    // create path and map variables
    String localVarPath = "/v2.1/oauth2/revoke";

    // query params
    java.util.List<Pair> localVarQueryParams = new java.util.ArrayList<Pair>();
    java.util.List<Pair> localVarCollectionQueryParams = new java.util.ArrayList<Pair>();
    java.util.Map<String, String> localVarHeaderParams = new java.util.HashMap<String, String>();
    java.util.Map<String, Object> localVarFormParams = new java.util.HashMap<String, Object>();

    final String[] localVarAccepts = {"application/json"};
    final String localVarAccept = apiClient.selectHeaderAccept(localVarAccepts);

    final String[] localVarContentTypes = {};

    final String localVarContentType = apiClient.selectHeaderContentType(localVarContentTypes);

    String[] localVarAuthNames = new String[] {"docusignAccessCode"};

    apiClient.invokeAPI(
        localVarPath,
        "POST",
        localVarQueryParams,
        localVarCollectionQueryParams,
        localVarPostBody,
        localVarHeaderParams,
        localVarFormParams,
        localVarAccept,
        localVarContentType,
        localVarAuthNames,
        null);
    return new ApiResponse<Object>(apiClient.getStatusCode(), apiClient.getResponseHeaders(), null);
  }

  /**
   * Updates the password for a specified user.. Updates the password for a specified user.
   *
   * @param loginPart Currently, only the value **password** is supported. (required)
   * @param userPasswordInformation (optional)
   * @throws ApiException if fails to make API call
   */
  public void updatePassword(String loginPart, UserPasswordInformation userPasswordInformation)
      throws ApiException {
    updatePasswordWithHttpInfo(loginPart, userPasswordInformation);
  }

  /**
   * Updates the password for a specified user. Updates the password for a specified user.
   *
   * @param loginPart Currently, only the value **password** is supported. (required)
   * @param userPasswordInformation (optional)
   * @throws ApiException if fails to make API call
   */
  public ApiResponse<Object> updatePasswordWithHttpInfo(
      String loginPart, UserPasswordInformation userPasswordInformation) throws ApiException {
    Object localVarPostBody = userPasswordInformation;

    // verify the required parameter 'loginPart' is set
    if (loginPart == null) {
      throw new ApiException(
          400, "Missing the required parameter 'loginPart' when calling updatePassword");
    }

    // create path and map variables
    String localVarPath =
        "/v2.1/login_information/{loginPart}"
            .replaceAll("\\{" + "loginPart" + "\\}", apiClient.escapeString(loginPart.toString()));

    // query params
    java.util.List<Pair> localVarQueryParams = new java.util.ArrayList<Pair>();
    java.util.List<Pair> localVarCollectionQueryParams = new java.util.ArrayList<Pair>();
    java.util.Map<String, String> localVarHeaderParams = new java.util.HashMap<String, String>();
    java.util.Map<String, Object> localVarFormParams = new java.util.HashMap<String, Object>();

    final String[] localVarAccepts = {"application/json"};
    final String localVarAccept = apiClient.selectHeaderAccept(localVarAccepts);

    final String[] localVarContentTypes = {};

    final String localVarContentType = apiClient.selectHeaderContentType(localVarContentTypes);

    String[] localVarAuthNames = new String[] {"docusignAccessCode"};

    apiClient.invokeAPI(
        localVarPath,
        "PUT",
        localVarQueryParams,
        localVarCollectionQueryParams,
        localVarPostBody,
        localVarHeaderParams,
        localVarFormParams,
        localVarAccept,
        localVarContentType,
        localVarAuthNames,
        null);
    return new ApiResponse<Object>(apiClient.getStatusCode(), apiClient.getResponseHeaders(), null);
  }

  /**
   * Adds social account for a user.. Adds a new social account to a user&#39;s account.
   *
   * @param accountId The external account number (int) or account ID Guid. (required)
   * @param userId The user ID of the user being accessed. Generally this is the user ID of the
   *     authenticated user, but if the authenticated user is an Admin on the account, this may be
   *     another user the Admin user is accessing. (required)
   * @param socialAccountInformation (optional)
   * @throws ApiException if fails to make API call
   */
  public void updateSocialLogin(
      String accountId, String userId, SocialAccountInformation socialAccountInformation)
      throws ApiException {
    updateSocialLoginWithHttpInfo(accountId, userId, socialAccountInformation);
  }

  /**
   * Adds social account for a user. Adds a new social account to a user&#39;s account.
   *
   * @param accountId The external account number (int) or account ID Guid. (required)
   * @param userId The user ID of the user being accessed. Generally this is the user ID of the
   *     authenticated user, but if the authenticated user is an Admin on the account, this may be
   *     another user the Admin user is accessing. (required)
   * @param socialAccountInformation (optional)
   * @throws ApiException if fails to make API call
   */
  public ApiResponse<Object> updateSocialLoginWithHttpInfo(
      String accountId, String userId, SocialAccountInformation socialAccountInformation)
      throws ApiException {
    Object localVarPostBody = socialAccountInformation;

    // verify the required parameter 'accountId' is set
    if (accountId == null) {
      throw new ApiException(
          400, "Missing the required parameter 'accountId' when calling updateSocialLogin");
    }

    // verify the required parameter 'userId' is set
    if (userId == null) {
      throw new ApiException(
          400, "Missing the required parameter 'userId' when calling updateSocialLogin");
    }

    // create path and map variables
    String localVarPath =
        "/v2.1/accounts/{accountId}/users/{userId}/social"
            .replaceAll("\\{" + "accountId" + "\\}", apiClient.escapeString(accountId.toString()))
            .replaceAll("\\{" + "userId" + "\\}", apiClient.escapeString(userId.toString()));

    // query params
    java.util.List<Pair> localVarQueryParams = new java.util.ArrayList<Pair>();
    java.util.List<Pair> localVarCollectionQueryParams = new java.util.ArrayList<Pair>();
    java.util.Map<String, String> localVarHeaderParams = new java.util.HashMap<String, String>();
    java.util.Map<String, Object> localVarFormParams = new java.util.HashMap<String, Object>();

    final String[] localVarAccepts = {"application/json"};
    final String localVarAccept = apiClient.selectHeaderAccept(localVarAccepts);

    final String[] localVarContentTypes = {};

    final String localVarContentType = apiClient.selectHeaderContentType(localVarContentTypes);

    String[] localVarAuthNames = new String[] {"docusignAccessCode"};

    apiClient.invokeAPI(
        localVarPath,
        "PUT",
        localVarQueryParams,
        localVarCollectionQueryParams,
        localVarPostBody,
        localVarHeaderParams,
        localVarFormParams,
        localVarAccept,
        localVarContentType,
        localVarAuthNames,
        null);
    return new ApiResponse<Object>(apiClient.getStatusCode(), apiClient.getResponseHeaders(), null);
  }
}
