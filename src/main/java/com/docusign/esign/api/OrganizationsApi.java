package com.docusign.esign.api;

import com.docusign.esign.client.ApiClient;
import com.docusign.esign.client.ApiException;
import com.docusign.esign.client.ApiResponse;
import com.docusign.esign.client.Configuration;
import com.docusign.esign.client.Pair;

/** OrganizationsApi class. */
public class OrganizationsApi {
  private ApiClient apiClient;

  /** OrganizationsApi. */
  public OrganizationsApi() {
    this(Configuration.getDefaultApiClient());
  }

  /** OrganizationsApi. */
  public OrganizationsApi(ApiClient apiClient) {
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
   * Retrieves org level report by correlation id and site..
   *
   * @param organizationId (required)
   * @param reportCorrelationId (required)
   * @throws ApiException if fails to make API call
   */
  public void getReportV2(String organizationId, String reportCorrelationId) throws ApiException {
    getReportV2WithHttpInfo(organizationId, reportCorrelationId);
  }

  /**
   * Retrieves org level report by correlation id and site.
   *
   * @param organizationId (required)
   * @param reportCorrelationId (required)
   * @throws ApiException if fails to make API call
   */
  public ApiResponse<Object> getReportV2WithHttpInfo(
      String organizationId, String reportCorrelationId) throws ApiException {
    Object localVarPostBody = "{}";

    // verify the required parameter 'organizationId' is set
    if (organizationId == null) {
      throw new ApiException(
          400, "Missing the required parameter 'organizationId' when calling getReportV2");
    }

    // verify the required parameter 'reportCorrelationId' is set
    if (reportCorrelationId == null) {
      throw new ApiException(
          400, "Missing the required parameter 'reportCorrelationId' when calling getReportV2");
    }

    // create path and map variables
    String localVarPath =
        "/v2.1/organization_reporting/{organizationId}/reportsv2/{reportCorrelationId}"
            .replaceAll(
                "\\{" + "organizationId" + "\\}", apiClient.escapeString(organizationId.toString()))
            .replaceAll(
                "\\{" + "reportCorrelationId" + "\\}",
                apiClient.escapeString(reportCorrelationId.toString()));

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
        "GET",
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
