package com.docusign.esign.api;

import com.docusign.esign.client.ApiClient;
import com.docusign.esign.client.ApiException;
import com.docusign.esign.client.ApiResponse;
import com.docusign.esign.client.Configuration;
import com.docusign.esign.client.Pair;
import com.docusign.esign.model.*;
import com.docusign.esign.override.jarkarta.GenericType;

/** SigningGroupsApi class. */
public class SigningGroupsApi {
  private ApiClient apiClient;

  /** SigningGroupsApi. */
  public SigningGroupsApi() {
    this(Configuration.getDefaultApiClient());
  }

  /** SigningGroupsApi. */
  public SigningGroupsApi(ApiClient apiClient) {
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

  /// <summary>
  /// Gets a list of the Signing Groups in an account. Retrieves a list of all signing groups in the
  // specified account.
  /// </summary>

  /** CallListOptions Class. */
  public class CallListOptions {
    private String groupType = null;
    private String includeUsers = null;

    /** setGroupType method. */
    public void setGroupType(String groupType) {
      this.groupType = groupType;
    }

    /**
     * getGroupType method.
     *
     * @return String
     */
    public String getGroupType() {
      return this.groupType;
    }

    /** setIncludeUsers method. */
    public void setIncludeUsers(String includeUsers) {
      this.includeUsers = includeUsers;
    }

    /**
     * getIncludeUsers method.
     *
     * @return String
     */
    public String getIncludeUsers() {
      return this.includeUsers;
    }
  }

  /**
   * Gets a list of the Signing Groups in an account.. Retrieves a list of all signing groups in the
   * specified account.
   *
   * @param accountId The external account number (int) or account ID Guid. (required)
   * @return SigningGroupInformation
   */
  public SigningGroupInformation callList(String accountId) throws ApiException {
    return callList(accountId, null);
  }

  /**
   * Gets a list of the Signing Groups in an account.. Retrieves a list of all signing groups in the
   * specified account.
   *
   * @param accountId The external account number (int) or account ID Guid. (required)
   * @param options for modifying the method behavior.
   * @return SigningGroupInformation
   * @throws ApiException if fails to make API call
   */
  public SigningGroupInformation callList(
      String accountId, SigningGroupsApi.CallListOptions options) throws ApiException {
    ApiResponse<SigningGroupInformation> localVarResponse =
        callListWithHttpInfo(accountId, options);
    return localVarResponse.getData();
  }

  /**
   * Gets a list of the Signing Groups in an account. Retrieves a list of all signing groups in the
   * specified account.
   *
   * @param accountId The external account number (int) or account ID Guid. (required)
   * @param options for modifying the method behavior.
   * @return SigningGroupInformation
   * @throws ApiException if fails to make API call
   */
  public ApiResponse<SigningGroupInformation> callListWithHttpInfo(
      String accountId, SigningGroupsApi.CallListOptions options) throws ApiException {
    Object localVarPostBody = "{}";

    // verify the required parameter 'accountId' is set
    if (accountId == null) {
      throw new ApiException(
          400, "Missing the required parameter 'accountId' when calling callList");
    }

    // create path and map variables
    String localVarPath =
        "/v2.1/accounts/{accountId}/signing_groups"
            .replaceAll("\\{" + "accountId" + "\\}", apiClient.escapeString(accountId.toString()));

    // query params
    java.util.List<Pair> localVarQueryParams = new java.util.ArrayList<Pair>();
    java.util.List<Pair> localVarCollectionQueryParams = new java.util.ArrayList<Pair>();
    java.util.Map<String, String> localVarHeaderParams = new java.util.HashMap<String, String>();
    java.util.Map<String, Object> localVarFormParams = new java.util.HashMap<String, Object>();

    if (options != null) {
      localVarQueryParams.addAll(apiClient.parameterToPair("group_type", options.groupType));
    }
    if (options != null) {
      localVarQueryParams.addAll(apiClient.parameterToPair("include_users", options.includeUsers));
    }

    final String[] localVarAccepts = {"application/json"};
    final String localVarAccept = apiClient.selectHeaderAccept(localVarAccepts);

    final String[] localVarContentTypes = {};

    final String localVarContentType = apiClient.selectHeaderContentType(localVarContentTypes);

    String[] localVarAuthNames = new String[] {"docusignAccessCode"};

    GenericType<SigningGroupInformation> localVarReturnType =
        new GenericType<SigningGroupInformation>() {};
    SigningGroupInformation localVarResponse =
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
    return new ApiResponse<SigningGroupInformation>(
        apiClient.getStatusCode(), apiClient.getResponseHeaders(), localVarResponse);
  }

  /**
   * Creates a signing group. . Creates one or more signing groups. Multiple signing groups can be
   * created in one call. Only users with account administrator privileges can create signing
   * groups. An account can have a maximum of 50 signing groups. Each signing group can have a
   * maximum of 50 group members. Signing groups can be used by any account user.
   *
   * @param accountId The external account number (int) or account ID Guid. (required)
   * @param signingGroupInformation (optional)
   * @return SigningGroupInformation
   * @throws ApiException if fails to make API call
   */
  public SigningGroupInformation createList(
      String accountId, SigningGroupInformation signingGroupInformation) throws ApiException {
    ApiResponse<SigningGroupInformation> localVarResponse =
        createListWithHttpInfo(accountId, signingGroupInformation);
    return localVarResponse.getData();
  }

  /**
   * Creates a signing group. Creates one or more signing groups. Multiple signing groups can be
   * created in one call. Only users with account administrator privileges can create signing
   * groups. An account can have a maximum of 50 signing groups. Each signing group can have a
   * maximum of 50 group members. Signing groups can be used by any account user.
   *
   * @param accountId The external account number (int) or account ID Guid. (required)
   * @param signingGroupInformation (optional)
   * @return SigningGroupInformation
   * @throws ApiException if fails to make API call
   */
  public ApiResponse<SigningGroupInformation> createListWithHttpInfo(
      String accountId, SigningGroupInformation signingGroupInformation) throws ApiException {
    Object localVarPostBody = signingGroupInformation;

    // verify the required parameter 'accountId' is set
    if (accountId == null) {
      throw new ApiException(
          400, "Missing the required parameter 'accountId' when calling createList");
    }

    // create path and map variables
    String localVarPath =
        "/v2.1/accounts/{accountId}/signing_groups"
            .replaceAll("\\{" + "accountId" + "\\}", apiClient.escapeString(accountId.toString()));

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

    GenericType<SigningGroupInformation> localVarReturnType =
        new GenericType<SigningGroupInformation>() {};
    SigningGroupInformation localVarResponse =
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
    return new ApiResponse<SigningGroupInformation>(
        apiClient.getStatusCode(), apiClient.getResponseHeaders(), localVarResponse);
  }

  /**
   * Deletes one or more signing groups.. Deletes one or more signing groups in the specified
   * account.
   *
   * @param accountId The external account number (int) or account ID Guid. (required)
   * @param signingGroupInformation (optional)
   * @return SigningGroupInformation
   * @throws ApiException if fails to make API call
   */
  public SigningGroupInformation deleteList(
      String accountId, SigningGroupInformation signingGroupInformation) throws ApiException {
    ApiResponse<SigningGroupInformation> localVarResponse =
        deleteListWithHttpInfo(accountId, signingGroupInformation);
    return localVarResponse.getData();
  }

  /**
   * Deletes one or more signing groups. Deletes one or more signing groups in the specified
   * account.
   *
   * @param accountId The external account number (int) or account ID Guid. (required)
   * @param signingGroupInformation (optional)
   * @return SigningGroupInformation
   * @throws ApiException if fails to make API call
   */
  public ApiResponse<SigningGroupInformation> deleteListWithHttpInfo(
      String accountId, SigningGroupInformation signingGroupInformation) throws ApiException {
    Object localVarPostBody = signingGroupInformation;

    // verify the required parameter 'accountId' is set
    if (accountId == null) {
      throw new ApiException(
          400, "Missing the required parameter 'accountId' when calling deleteList");
    }

    // create path and map variables
    String localVarPath =
        "/v2.1/accounts/{accountId}/signing_groups"
            .replaceAll("\\{" + "accountId" + "\\}", apiClient.escapeString(accountId.toString()));

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

    GenericType<SigningGroupInformation> localVarReturnType =
        new GenericType<SigningGroupInformation>() {};
    SigningGroupInformation localVarResponse =
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
            localVarReturnType);
    return new ApiResponse<SigningGroupInformation>(
        apiClient.getStatusCode(), apiClient.getResponseHeaders(), localVarResponse);
  }

  /**
   * Deletes one or more members from a signing group.. Deletes one or more members from the
   * specified signing group.
   *
   * @param accountId The external account number (int) or account ID Guid. (required)
   * @param signingGroupId (required)
   * @param signingGroupUsers (optional)
   * @return SigningGroupUsers
   * @throws ApiException if fails to make API call
   */
  public SigningGroupUsers deleteUsers(
      String accountId, String signingGroupId, SigningGroupUsers signingGroupUsers)
      throws ApiException {
    ApiResponse<SigningGroupUsers> localVarResponse =
        deleteUsersWithHttpInfo(accountId, signingGroupId, signingGroupUsers);
    return localVarResponse.getData();
  }

  /**
   * Deletes one or more members from a signing group. Deletes one or more members from the
   * specified signing group.
   *
   * @param accountId The external account number (int) or account ID Guid. (required)
   * @param signingGroupId (required)
   * @param signingGroupUsers (optional)
   * @return SigningGroupUsers
   * @throws ApiException if fails to make API call
   */
  public ApiResponse<SigningGroupUsers> deleteUsersWithHttpInfo(
      String accountId, String signingGroupId, SigningGroupUsers signingGroupUsers)
      throws ApiException {
    Object localVarPostBody = signingGroupUsers;

    // verify the required parameter 'accountId' is set
    if (accountId == null) {
      throw new ApiException(
          400, "Missing the required parameter 'accountId' when calling deleteUsers");
    }

    // verify the required parameter 'signingGroupId' is set
    if (signingGroupId == null) {
      throw new ApiException(
          400, "Missing the required parameter 'signingGroupId' when calling deleteUsers");
    }

    // create path and map variables
    String localVarPath =
        "/v2.1/accounts/{accountId}/signing_groups/{signingGroupId}/users"
            .replaceAll("\\{" + "accountId" + "\\}", apiClient.escapeString(accountId.toString()))
            .replaceAll(
                "\\{" + "signingGroupId" + "\\}",
                apiClient.escapeString(signingGroupId.toString()));

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

    GenericType<SigningGroupUsers> localVarReturnType = new GenericType<SigningGroupUsers>() {};
    SigningGroupUsers localVarResponse =
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
            localVarReturnType);
    return new ApiResponse<SigningGroupUsers>(
        apiClient.getStatusCode(), apiClient.getResponseHeaders(), localVarResponse);
  }

  /**
   * Gets information about a signing group. . Retrieves information, including group member
   * information, for the specified signing group.
   *
   * @param accountId The external account number (int) or account ID Guid. (required)
   * @param signingGroupId (required)
   * @return SigningGroup
   * @throws ApiException if fails to make API call
   */
  public SigningGroup get(String accountId, String signingGroupId) throws ApiException {
    ApiResponse<SigningGroup> localVarResponse = getWithHttpInfo(accountId, signingGroupId);
    return localVarResponse.getData();
  }

  /**
   * Gets information about a signing group. Retrieves information, including group member
   * information, for the specified signing group.
   *
   * @param accountId The external account number (int) or account ID Guid. (required)
   * @param signingGroupId (required)
   * @return SigningGroup
   * @throws ApiException if fails to make API call
   */
  public ApiResponse<SigningGroup> getWithHttpInfo(String accountId, String signingGroupId)
      throws ApiException {
    Object localVarPostBody = "{}";

    // verify the required parameter 'accountId' is set
    if (accountId == null) {
      throw new ApiException(400, "Missing the required parameter 'accountId' when calling get");
    }

    // verify the required parameter 'signingGroupId' is set
    if (signingGroupId == null) {
      throw new ApiException(
          400, "Missing the required parameter 'signingGroupId' when calling get");
    }

    // create path and map variables
    String localVarPath =
        "/v2.1/accounts/{accountId}/signing_groups/{signingGroupId}"
            .replaceAll("\\{" + "accountId" + "\\}", apiClient.escapeString(accountId.toString()))
            .replaceAll(
                "\\{" + "signingGroupId" + "\\}",
                apiClient.escapeString(signingGroupId.toString()));

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

    GenericType<SigningGroup> localVarReturnType = new GenericType<SigningGroup>() {};
    SigningGroup localVarResponse =
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
    return new ApiResponse<SigningGroup>(
        apiClient.getStatusCode(), apiClient.getResponseHeaders(), localVarResponse);
  }

  /**
   * Gets a list of members in a Signing Group.. Retrieves the list of members in the specified
   * Signing Group.
   *
   * @param accountId The external account number (int) or account ID Guid. (required)
   * @param signingGroupId (required)
   * @return SigningGroupUsers
   * @throws ApiException if fails to make API call
   */
  public SigningGroupUsers listUsers(String accountId, String signingGroupId) throws ApiException {
    ApiResponse<SigningGroupUsers> localVarResponse =
        listUsersWithHttpInfo(accountId, signingGroupId);
    return localVarResponse.getData();
  }

  /**
   * Gets a list of members in a Signing Group. Retrieves the list of members in the specified
   * Signing Group.
   *
   * @param accountId The external account number (int) or account ID Guid. (required)
   * @param signingGroupId (required)
   * @return SigningGroupUsers
   * @throws ApiException if fails to make API call
   */
  public ApiResponse<SigningGroupUsers> listUsersWithHttpInfo(
      String accountId, String signingGroupId) throws ApiException {
    Object localVarPostBody = "{}";

    // verify the required parameter 'accountId' is set
    if (accountId == null) {
      throw new ApiException(
          400, "Missing the required parameter 'accountId' when calling listUsers");
    }

    // verify the required parameter 'signingGroupId' is set
    if (signingGroupId == null) {
      throw new ApiException(
          400, "Missing the required parameter 'signingGroupId' when calling listUsers");
    }

    // create path and map variables
    String localVarPath =
        "/v2.1/accounts/{accountId}/signing_groups/{signingGroupId}/users"
            .replaceAll("\\{" + "accountId" + "\\}", apiClient.escapeString(accountId.toString()))
            .replaceAll(
                "\\{" + "signingGroupId" + "\\}",
                apiClient.escapeString(signingGroupId.toString()));

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

    GenericType<SigningGroupUsers> localVarReturnType = new GenericType<SigningGroupUsers>() {};
    SigningGroupUsers localVarResponse =
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
    return new ApiResponse<SigningGroupUsers>(
        apiClient.getStatusCode(), apiClient.getResponseHeaders(), localVarResponse);
  }

  /**
   * Updates a signing group. . Updates signing group name and member information. You can also add
   * new members to the signing group. A signing group can have a maximum of 50 members.
   *
   * @param accountId The external account number (int) or account ID Guid. (required)
   * @param signingGroupId (required)
   * @param signingGroup (optional)
   * @return SigningGroup
   * @throws ApiException if fails to make API call
   */
  public SigningGroup update(String accountId, String signingGroupId, SigningGroup signingGroup)
      throws ApiException {
    ApiResponse<SigningGroup> localVarResponse =
        updateWithHttpInfo(accountId, signingGroupId, signingGroup);
    return localVarResponse.getData();
  }

  /**
   * Updates a signing group. Updates signing group name and member information. You can also add
   * new members to the signing group. A signing group can have a maximum of 50 members.
   *
   * @param accountId The external account number (int) or account ID Guid. (required)
   * @param signingGroupId (required)
   * @param signingGroup (optional)
   * @return SigningGroup
   * @throws ApiException if fails to make API call
   */
  public ApiResponse<SigningGroup> updateWithHttpInfo(
      String accountId, String signingGroupId, SigningGroup signingGroup) throws ApiException {
    Object localVarPostBody = signingGroup;

    // verify the required parameter 'accountId' is set
    if (accountId == null) {
      throw new ApiException(400, "Missing the required parameter 'accountId' when calling update");
    }

    // verify the required parameter 'signingGroupId' is set
    if (signingGroupId == null) {
      throw new ApiException(
          400, "Missing the required parameter 'signingGroupId' when calling update");
    }

    // create path and map variables
    String localVarPath =
        "/v2.1/accounts/{accountId}/signing_groups/{signingGroupId}"
            .replaceAll("\\{" + "accountId" + "\\}", apiClient.escapeString(accountId.toString()))
            .replaceAll(
                "\\{" + "signingGroupId" + "\\}",
                apiClient.escapeString(signingGroupId.toString()));

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

    GenericType<SigningGroup> localVarReturnType = new GenericType<SigningGroup>() {};
    SigningGroup localVarResponse =
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
            localVarReturnType);
    return new ApiResponse<SigningGroup>(
        apiClient.getStatusCode(), apiClient.getResponseHeaders(), localVarResponse);
  }

  /**
   * Updates signing group names.. Updates the name of one or more existing signing groups.
   *
   * @param accountId The external account number (int) or account ID Guid. (required)
   * @param signingGroupInformation (optional)
   * @return SigningGroupInformation
   * @throws ApiException if fails to make API call
   */
  public SigningGroupInformation updateList(
      String accountId, SigningGroupInformation signingGroupInformation) throws ApiException {
    ApiResponse<SigningGroupInformation> localVarResponse =
        updateListWithHttpInfo(accountId, signingGroupInformation);
    return localVarResponse.getData();
  }

  /**
   * Updates signing group names. Updates the name of one or more existing signing groups.
   *
   * @param accountId The external account number (int) or account ID Guid. (required)
   * @param signingGroupInformation (optional)
   * @return SigningGroupInformation
   * @throws ApiException if fails to make API call
   */
  public ApiResponse<SigningGroupInformation> updateListWithHttpInfo(
      String accountId, SigningGroupInformation signingGroupInformation) throws ApiException {
    Object localVarPostBody = signingGroupInformation;

    // verify the required parameter 'accountId' is set
    if (accountId == null) {
      throw new ApiException(
          400, "Missing the required parameter 'accountId' when calling updateList");
    }

    // create path and map variables
    String localVarPath =
        "/v2.1/accounts/{accountId}/signing_groups"
            .replaceAll("\\{" + "accountId" + "\\}", apiClient.escapeString(accountId.toString()));

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

    GenericType<SigningGroupInformation> localVarReturnType =
        new GenericType<SigningGroupInformation>() {};
    SigningGroupInformation localVarResponse =
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
            localVarReturnType);
    return new ApiResponse<SigningGroupInformation>(
        apiClient.getStatusCode(), apiClient.getResponseHeaders(), localVarResponse);
  }

  /**
   * Adds members to a signing group. . Adds one or more new members to a signing group. A signing
   * group can have a maximum of 50 members.
   *
   * @param accountId The external account number (int) or account ID Guid. (required)
   * @param signingGroupId (required)
   * @param signingGroupUsers (optional)
   * @return SigningGroupUsers
   * @throws ApiException if fails to make API call
   */
  public SigningGroupUsers updateUsers(
      String accountId, String signingGroupId, SigningGroupUsers signingGroupUsers)
      throws ApiException {
    ApiResponse<SigningGroupUsers> localVarResponse =
        updateUsersWithHttpInfo(accountId, signingGroupId, signingGroupUsers);
    return localVarResponse.getData();
  }

  /**
   * Adds members to a signing group. Adds one or more new members to a signing group. A signing
   * group can have a maximum of 50 members.
   *
   * @param accountId The external account number (int) or account ID Guid. (required)
   * @param signingGroupId (required)
   * @param signingGroupUsers (optional)
   * @return SigningGroupUsers
   * @throws ApiException if fails to make API call
   */
  public ApiResponse<SigningGroupUsers> updateUsersWithHttpInfo(
      String accountId, String signingGroupId, SigningGroupUsers signingGroupUsers)
      throws ApiException {
    Object localVarPostBody = signingGroupUsers;

    // verify the required parameter 'accountId' is set
    if (accountId == null) {
      throw new ApiException(
          400, "Missing the required parameter 'accountId' when calling updateUsers");
    }

    // verify the required parameter 'signingGroupId' is set
    if (signingGroupId == null) {
      throw new ApiException(
          400, "Missing the required parameter 'signingGroupId' when calling updateUsers");
    }

    // create path and map variables
    String localVarPath =
        "/v2.1/accounts/{accountId}/signing_groups/{signingGroupId}/users"
            .replaceAll("\\{" + "accountId" + "\\}", apiClient.escapeString(accountId.toString()))
            .replaceAll(
                "\\{" + "signingGroupId" + "\\}",
                apiClient.escapeString(signingGroupId.toString()));

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

    GenericType<SigningGroupUsers> localVarReturnType = new GenericType<SigningGroupUsers>() {};
    SigningGroupUsers localVarResponse =
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
            localVarReturnType);
    return new ApiResponse<SigningGroupUsers>(
        apiClient.getStatusCode(), apiClient.getResponseHeaders(), localVarResponse);
  }
}
