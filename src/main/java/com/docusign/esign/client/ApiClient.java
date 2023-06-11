package com.docusign.esign.client;

import com.docusign.esign.client.auth.*;
import com.docusign.esign.override.jarkarta.GenericType;
import com.docusign.esign.override.jarkarta.UriBuilder;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.csv.CsvMapper;
import com.fasterxml.jackson.dataformat.csv.CsvSchema;
import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.text.DateFormat;
import java.util.*;
import java.util.Map.Entry;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.entity.EntityBuilder;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpEntityEnclosingRequestBase;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpHead;
import org.apache.http.client.methods.HttpPatch;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicHeader;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest.AuthenticationRequestBuilder;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest.TokenRequestBuilder;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;

/** ApiClient class. */
public class ApiClient {

  protected Map<String, String> defaultHeaderMap = new HashMap<String, String>();
  // Rest API base path constants
  /** live/production base path. */
  public static final String PRODUCTION_REST_BASEPATH = "https://www.docusign.net/restapi";
  /** sandbox/demo base path. */
  public static final String DEMO_REST_BASEPATH = "https://demo.docusign.net/restapi";
  /** stage base path. */
  public static final String STAGE_REST_BASEPATH = "https://stage.docusign.net/restapi";

  private String basePath = PRODUCTION_REST_BASEPATH;
  private String oAuthBasePath = OAuth.PRODUCTION_OAUTH_BASEPATH;
  protected boolean debugging = false;
  protected int connectionTimeout = 0;
  private int readTimeout = 0;

  protected CloseableHttpClient httpClient;
  protected JSON json;
  protected String tempFolderPath = null;

  protected Map<String, Authentication> authentications;

  private int statusCode;
  private Map<String, List<String>> responseHeaders;

  protected DateFormat dateFormat;
  // private SSLContext sslContext = null;

  // Specific http client
  protected RequestConfig config = RequestConfig.DEFAULT;

  /** ApiClient constructor. */
  public ApiClient() {
    json = new JSON();
    httpClient = buildHttpClient(debugging);

    this.dateFormat = new RFC3339DateFormat();
    String javaVersion = System.getProperty("java.version");

    // Set default User-Agent.
    setUserAgent("/SDK/4.3.0/Java/");

    // Setup authentications (key: authentication name, value: authentication).
    authentications = new HashMap<String, Authentication>();
    authentications.put("docusignAccessCode", new OAuth());

    // Derive the OAuth base path from the Rest API base url
    this.deriveOAuthBasePathFromRestBasePath();
  }

  private static class LocalNameValuePair implements NameValuePair {

    private String name;
    private String value;

    @Override
    public String getName() {
      return name;
    }

    @Override
    public String getValue() {
      return value;
    }

    public static NameValuePair create(String name, String value) {
      LocalNameValuePair v = new LocalNameValuePair();
      v.name = name;
      v.value = value;
      return v;
    }
  }

  /**
   * buildDefaultDateFormat method.
   *
   * @return DateFormat
   */
  public static DateFormat buildDefaultDateFormat() {
    return new RFC3339DateFormat();
  }

  /**
   * ApiClient constructor.
   *
   * @param basePath The base path to create the client with
   */
  public ApiClient(String basePath) {
    this();
    this.basePath = basePath;
    this.deriveOAuthBasePathFromRestBasePath();
  }

  /**
   * ApiClient constructor.
   *
   * @param oAuthBasePath The base path to create the client with
   * @param authNames The authentication names
   */
  public ApiClient(String oAuthBasePath, String[] authNames) {
    this();
    this.setOAuthBasePath(oAuthBasePath);
    for (String authName : authNames) {
      Authentication auth;
      if ("docusignAccessCode".equals(authName)) {
        auth =
            new OAuth(
                httpClient,
                OAuthFlow.accessCode,
                oAuthBasePath + "/oauth/auth",
                oAuthBasePath + "/oauth/token",
                "all");
      } else if ("docusignApiKey".equals(authName)) {
        auth = new ApiKeyAuth("header", "docusignApiKey");
      } else {
        throw new RuntimeException(
            "auth name \"" + authName + "\" not found in available auth names");
      }
      addAuthorization(authName, auth);
    }
  }

  /**
   * Basic constructor for single auth name.
   *
   * @param oAuthBasePath the basepath
   * @param authName the auth name
   */
  public ApiClient(String oAuthBasePath, String authName) {
    this(oAuthBasePath, new String[] {authName});
  }

  /**
   * Helper constructor for OAuth2.
   *
   * @param oAuthBasePath The API base path
   * @param authName the authentication method name ("oauth" or "api_key")
   * @param clientId OAuth2 Client ID
   * @param secret OAuth2 Client secret
   */
  public ApiClient(String oAuthBasePath, String authName, String clientId, String secret) {
    this(oAuthBasePath, authName);
    this.getTokenEndPoint().setClientId(clientId).setClientSecret(secret);
  }

  /**
   * Build the Client used to make HTTP requests with the latest settings, i.e. objectMapper and
   * debugging. TODO: better to use the Builder Pattern?
   *
   * @return API client
   */
  public ApiClient rebuildHttpClient() {
    return setDebugging(debugging);
  }

  /**
   * Returns the current object mapper used for JSON serialization/deserialization.
   *
   * <p>Note: If you make changes to the object mapper, remember to set it back via <code>
   * setObjectMapper</code> in order to trigger HTTP client rebuilding.
   *
   * @return Object mapper
   */
  public ObjectMapper getObjectMapper() {
    return json.getObjectMapper();
  }

  /**
   * Set the object mapper of client.
   *
   * @return API client
   */
  public ApiClient setObjectMapper(ObjectMapper objectMapper) {
    json.setObjectMapper(objectMapper);
    // Need to rebuild the Client as it depends on object mapper.
    rebuildHttpClient();
    return this;
  }

  /**
   * Gets the JSON instance to do JSON serialization and deserialization.
   *
   * @return JSON
   */
  public JSON getJSON() {
    return json;
  }

  /**
   * Gets the API client.
   *
   * @return Client
   */
  public CloseableHttpClient getHttpClient() {
    return httpClient;
  }

  /**
   * Sets the API client.
   *
   * @return ApiClient
   */
  public ApiClient setHttpClient(CloseableHttpClient httpClient) {
    this.httpClient = httpClient;
    return this;
  }

  /**
   * Gets the basepath.
   *
   * @return String
   */
  public String getBasePath() {
    return basePath;
  }

  /**
   * Sets the basepath.
   *
   * @return ApiClient
   */
  public ApiClient setBasePath(String basePath) {
    this.basePath = basePath;
    this.deriveOAuthBasePathFromRestBasePath();
    return this;
  }

  /**
   * Gets the status code of the previous request.
   *
   * @return Status code
   */
  public int getStatusCode() {
    return statusCode;
  }

  /**
   * Gets the response headers of the previous request.
   *
   * @return Response headers
   */
  public Map<String, List<String>> getResponseHeaders() {
    return responseHeaders;
  }

  /**
   * Get authentications (key: authentication name, value: authentication).
   *
   * @return Map of authentication object
   */
  public Map<String, Authentication> getAuthentications() {
    return authentications;
  }

  /**
   * Get authentication for the given name.
   *
   * @param authName The authentication name
   * @return The authentication, null if not found
   */
  public Authentication getAuthentication(String authName) {
    return authentications.get(authName);
  }

  /** Adds authorization. */
  public void addAuthorization(String authName, Authentication auth) {
    authentications.put(authName, auth);
  }

  /**
   * Helper method to set username for the first HTTP basic authentication.
   *
   * @param username Username
   */
  public void setUsername(String username) {
    for (Authentication auth : authentications.values()) {
      if (auth instanceof HttpBasicAuth) {
        ((HttpBasicAuth) auth).setUsername(username);
        return;
      }
    }
    throw new RuntimeException("No HTTP basic authentication configured!");
  }

  /**
   * Helper method to set password for the first HTTP basic authentication.
   *
   * @param password Password
   */
  public void setPassword(String password) {
    for (Authentication auth : authentications.values()) {
      if (auth instanceof HttpBasicAuth) {
        ((HttpBasicAuth) auth).setPassword(password);
        return;
      }
    }
    throw new RuntimeException("No HTTP basic authentication configured!");
  }

  /**
   * Helper method to set API key value for the first API key authentication.
   *
   * @param apiKey API key
   */
  public void setApiKey(String apiKey) {
    for (Authentication auth : authentications.values()) {
      if (auth instanceof ApiKeyAuth) {
        ((ApiKeyAuth) auth).setApiKey(apiKey);
        return;
      }
    }
    throw new RuntimeException("No API key authentication configured!");
  }

  /**
   * Helper method to set API key prefix for the first API key authentication.
   *
   * @param apiKeyPrefix API key prefix
   */
  public void setApiKeyPrefix(String apiKeyPrefix) {
    for (Authentication auth : authentications.values()) {
      if (auth instanceof ApiKeyAuth) {
        ((ApiKeyAuth) auth).setApiKeyPrefix(apiKeyPrefix);
        return;
      }
    }
    throw new RuntimeException("No API key authentication configured!");
  }

  /** Helper method to set access token for the first OAuth2 authentication. */
  public void updateAccessToken() {
    for (Authentication auth : authentications.values()) {
      if (auth instanceof OAuth) {
        try {
          ((OAuth) auth).updateAccessToken();
        } catch (ApiException e) {
          throw new RuntimeException(e.getMessage());
        }
        return;
      }
    }
    throw new RuntimeException("No OAuth2 authentication configured!");
  }

  /**
   * Helper method to preset the OAuth access token of the first OAuth found in the
   * apiAuthorizations (there should be only one).
   *
   * @param accessToken OAuth access token
   * @param expiresIn Validity period of the access token in seconds
   */
  public void setAccessToken(final String accessToken, final Long expiresIn) {
    for (Authentication auth : authentications.values()) {
      if (auth instanceof OAuth) {
        ((OAuth) auth).setAccessToken(accessToken, expiresIn);
        return;
      }
    }
    OAuth oAuth = new OAuth(null, null, null);
    oAuth.setAccessToken(accessToken, expiresIn);
    addAuthorization("docusignAccessCode", oAuth);
  }

  /**
   * Gets the access token.
   *
   * @return String
   */
  public String getAccessToken() {
    for (Authentication auth : authentications.values()) {
      if (auth instanceof OAuth) {
        return ((OAuth) auth).getAccessToken();
      }
    }
    return null;
  }

  /**
   * Set the User-Agent header's value (by adding to the default header map).
   *
   * @param userAgent Http user agent
   * @return API client
   */
  public ApiClient setUserAgent(String userAgent) {
    addDefaultHeader("User-Agent", userAgent);
    return this;
  }

  /**
   * Add a default header.
   *
   * @param key The header's key
   * @param value The header's value
   * @return API client
   */
  public ApiClient addDefaultHeader(String key, String value) {
    defaultHeaderMap.put(key, value);
    return this;
  }

  /**
   * Check that whether debugging is enabled for this API client.
   *
   * @return True if debugging is switched on
   */
  public boolean isDebugging() {
    return debugging;
  }

  /**
   * Enable/disable debugging for this API client.
   *
   * @param debugging To enable (true) or disable (false) debugging
   * @return API client
   */
  public ApiClient setDebugging(boolean debugging) {
    this.debugging = debugging;
    // Rebuild HTTP Client according to the new "debugging" value.
    this.httpClient = buildHttpClient(debugging);
    return this;
  }

  /**
   * The path of temporary folder used to store downloaded files from endpoints with file response.
   * The default value is <code>null</code>, i.e. using the system's default tempopary folder.
   *
   * @return Temp folder path
   */
  public String getTempFolderPath() {
    return tempFolderPath;
  }

  /**
   * Set temp folder path.
   *
   * @param tempFolderPath Temp folder path
   * @return API client
   */
  public ApiClient setTempFolderPath(String tempFolderPath) {
    this.tempFolderPath = tempFolderPath;
    return this;
  }

  /**
   * Connect timeout (in milliseconds).
   *
   * @return Connection timeout
   */
  public int getConnectTimeout() {
    return connectionTimeout;
  }

  /**
   * Set the connect timeout (in milliseconds). A value of 0 means no timeout, otherwise values must
   * be between 1 and {@link Integer#MAX_VALUE}.
   *
   * @param connectionTimeout Connection timeout in milliseconds
   * @return API client
   */
  public ApiClient setConnectTimeout(int connectionTimeout) {
    this.connectionTimeout = connectionTimeout;

    config = RequestConfig.copy(config).setConnectTimeout(connectionTimeout).build();

    httpClient = HttpClientBuilder.create().setDefaultRequestConfig(config).build();
    return this;
  }

  /**
   * read timeout (in milliseconds).
   *
   * @return Read timeout
   */
  public int getReadTimeout() {
    return readTimeout;
  }

  /**
   * Set the read timeout (in milliseconds). A value of 0 means no timeout, otherwise values must be
   * between 1 and {@link Integer#MAX_VALUE}.
   *
   * @param readTimeout Read timeout in milliseconds
   * @return API client
   */
  public ApiClient setReadTimeout(int readTimeout) {
    this.readTimeout = readTimeout;

    config =
        RequestConfig.copy(config)
            .setConnectionRequestTimeout(connectionTimeout)
            .setSocketTimeout(connectionTimeout)
            .build();

    httpClient = HttpClientBuilder.create().setDefaultRequestConfig(config).build();
    return this;
  }

  /**
   * Get the date format used to parse/format date parameters.
   *
   * @return Date format
   */
  public DateFormat getDateFormat() {
    return dateFormat;
  }

  /**
   * Set the date format used to parse/format date parameters.
   *
   * @param dateFormat Date format
   * @return API client
   */
  public ApiClient setDateFormat(DateFormat dateFormat) {
    this.dateFormat = dateFormat;
    // also set the date format for model (de)serialization with Date properties
    this.json.setDateFormat((DateFormat) dateFormat.clone());
    return this;
  }

  /**
   * Helper method to configure the token endpoint of the first oauth found in the authentications
   * (there should be only one).
   *
   * @return
   */
  public TokenRequestBuilder getTokenEndPoint() {
    for (Authentication auth : getAuthentications().values()) {
      if (auth instanceof OAuth) {
        OAuth oauth = (OAuth) auth;
        return oauth.getTokenRequestBuilder();
      }
    }
    return null;
  }

  /**
   * Helper method to configure authorization endpoint of the first oauth found in the
   * authentications (there should be only one).
   *
   * @return
   */
  public AuthenticationRequestBuilder getAuthorizationEndPoint() {
    for (Authentication auth : authentications.values()) {
      if (auth instanceof OAuth) {
        OAuth oauth = (OAuth) auth;
        return oauth.getAuthenticationRequestBuilder();
      }
    }
    return null;
  }

  /**
   * Helper method to configure the OAuth accessCode/implicit flow parameters.
   *
   * @param clientId OAuth2 client ID
   * @param clientSecret OAuth2 client secret
   * @param redirectURI OAuth2 redirect uri
   */
  public void configureAuthorizationFlow(String clientId, String clientSecret, String redirectURI) {
    for (Authentication auth : authentications.values()) {
      if (auth instanceof OAuth) {
        OAuth oauth = (OAuth) auth;
        oauth
            .getTokenRequestBuilder()
            .setClientId(clientId)
            .setClientSecret(clientSecret)
            .setRedirectURI(redirectURI);
        oauth.getAuthenticationRequestBuilder().setClientId(clientId).setRedirectURI(redirectURI);
        return;
      }
    }
  }

  public String getAuthorizationUri() throws OAuthSystemException {
    return getAuthorizationEndPoint().buildQueryMessage().getLocationUri();
  }

  /**
   * Helper method to configure the OAuth accessCode/implicit flow parameters.
   *
   * @param clientId OAuth2 client ID: Identifies the client making the request. Client applications
   *     may be scoped to a limited set of system access.
   * @param scopes the list of requested scopes. Values include {@link OAuth#Scope_SIGNATURE},
   *     {@link OAuth#Scope_EXTENDED}, {@link OAuth#Scope_IMPERSONATION}. You can also pass any
   *     advanced scope.
   * @param redirectUri this determines where to deliver the response containing the authorization
   *     code or access token.
   * @param responseType determines the response type of the authorization request. <br>
   *     <i>Note</i>: these response types are mutually exclusive for a client application. A
   *     public/native client application may only request a response type of "token"; a
   *     private/trusted client application may only request a response type of "code".
   * @param state Allows for arbitrary state that may be useful to your application. The value in
   *     this parameter will be round-tripped along with the response so you can make sure it didn't
   *     change.
   */
  public URI getAuthorizationUri(
      String clientId,
      java.util.List<String> scopes,
      String redirectUri,
      String responseType,
      String state)
      throws IllegalArgumentException, URISyntaxException {
    String formattedScopes = (scopes == null || scopes.size() < 1) ? "" : scopes.get(0);
    StringBuilder sb = new StringBuilder(formattedScopes);
    for (int i = 1; i < scopes.size(); i++) {
      sb.append("%20" + scopes.get(i));
    }

    UriBuilder builder =
        UriBuilder.fromUri(getOAuthBasePath())
            .scheme("https")
            .path("/oauth/auth")
            .queryParam("response_type", responseType)
            .queryParam("scope", sb.toString())
            .queryParam("client_id", clientId)
            .queryParam("redirect_uri", redirectUri);
    if (state != null) {
      builder = builder.queryParam("state", state);
    }
    return builder.build();
  }

  /**
   * Helper method to configure the OAuth accessCode/implicit flow parameters.
   *
   * @param clientId OAuth2 client ID: Identifies the client making the request. Client applications
   *     may be scoped to a limited set of system access.
   * @param scopes the list of requested scopes. Values include {@link OAuth#Scope_SIGNATURE},
   *     {@link OAuth#Scope_EXTENDED}, {@link OAuth#Scope_IMPERSONATION}. You can also pass any
   *     advanced scope.
   * @param redirectUri this determines where to deliver the response containing the authorization
   *     code or access token.
   * @param responseType determines the response type of the authorization request. <br>
   *     <i>Note</i>: these response types are mutually exclusive for a client application. A
   *     public/native client application may only request a response type of "token"; a
   *     private/trusted client application may only request a response type of "code".
   */
  public URI getAuthorizationUri(
      String clientId, java.util.List<String> scopes, String redirectUri, String responseType)
      throws IllegalArgumentException, URISyntaxException {
    return this.getAuthorizationUri(clientId, scopes, redirectUri, responseType, null);
  }

  private void deriveOAuthBasePathFromRestBasePath() {
    if (this.basePath == null) { // this case should not happen but just in case
      this.oAuthBasePath = OAuth.PRODUCTION_OAUTH_BASEPATH;
    } else if (this.basePath.startsWith("https://demo")
        || this.basePath.startsWith("http://demo")) {
      this.oAuthBasePath = OAuth.DEMO_OAUTH_BASEPATH;
    } else if (this.basePath.startsWith("https://stage")
        || this.basePath.startsWith("http://stage")) {
      this.oAuthBasePath = OAuth.STAGE_OAUTH_BASEPATH;
    } else {
      this.oAuthBasePath = OAuth.PRODUCTION_OAUTH_BASEPATH;
    }
  }

  private String getOAuthBasePath() {
    return this.oAuthBasePath;
  }

  /**
   * Sets the OAuth base path. Values include {@link OAuth#PRODUCTION_OAUTH_BASEPATH}, {@link
   * OAuth#DEMO_OAUTH_BASEPATH} and custom (e.g. "account-s.docusign.com").
   *
   * @param oAuthBasePath the new value for the OAuth base path
   * @return this instance of the ApiClient updated with the new OAuth base path
   */
  public ApiClient setOAuthBasePath(String oAuthBasePath) {
    this.oAuthBasePath = oAuthBasePath;
    return this;
  }

  /**
   * Helper method to configure the OAuth accessCode/implicit flow parameters.
   *
   * @param clientId OAuth2 client ID: Identifies the client making the request. Client applications
   *     may be scoped to a limited set of system access.
   * @param clientSecret the secret key you generated when you set up the integration in DocuSign
   *     Admin console.
   * @param code The authorization code that you received from the <i>getAuthorizationUri</i>
   *     callback.
   * @return OAuth.OAuthToken object.
   * @throws ApiException if the HTTP call status is different than 2xx.
   * @throws IOException if there is a problem while parsing the reponse object.
   * @see OAuth.OAuthToken
   */
  public OAuth.OAuthToken generateAccessToken(String clientId, String clientSecret, String code)
      throws ApiException, IOException {
    String clientStr =
        (clientId == null ? "" : clientId) + ":" + (clientSecret == null ? "" : clientSecret);
    java.util.Map<String, Object> form = new java.util.HashMap<>();
    form.put("code", code);
    form.put("grant_type", "authorization_code");

    CloseableHttpClient client = buildHttpClient(debugging);

    HttpPost request = new HttpPost("https://" + getOAuthBasePath() + "/oauth/token");
    request.setHeader(
        "Authorization",
        "Basic " + Base64.getEncoder().encodeToString(clientStr.getBytes("UTF-8")));
    request.setHeader("Cache-Control", "no-store");
    request.setHeader("Pragma", "no-cache");

    HttpEntity entity =
        serialize(null, form, ContentType.APPLICATION_FORM_URLENCODED.getMimeType());
    request.setEntity(entity);

    CloseableHttpResponse response = null;

    try {
      response = client.execute(request);

      if (!isSuccessful(response)) {
        throw createException(response);
      }

      GenericType<OAuth.OAuthToken> returnType = new GenericType<OAuth.OAuthToken>() {};
      return deserialize(response, returnType);
    } finally {
      try {
        if (response != null) {
          response.close();
        }
      } catch (Exception e) {
        // it's not critical, since the response object is local in method invokeAPI; that's fine,
        // just continue
      }
    }
  }
  
  public boolean isSuccessful(CloseableHttpResponse response){
      int c = response.getStatusLine().getStatusCode();
      return c >= HttpStatus.SC_OK  && c < HttpStatus.SC_MULTIPLE_CHOICES;
  }

  private ApiException createException(CloseableHttpResponse response) throws ApiException {
    String message = "error";
    String respBody = null;

    if (response.getEntity() != null) {
      try {
        respBody = new String(response.getEntity().getContent().readAllBytes());
        message =
            "Error while requesting server, received a non successful HTTP code "
                + response.getStatusLine().getStatusCode()
                + " with response Body: '"
                + respBody
                + "'";
      } catch (Exception e) {
        // e.printStackTrace();
      }
    }
    return new ApiException(
        response.getStatusLine().getStatusCode(),
        message,
        buildResponseHeaders(response),
        respBody);
  }

  /**
   * Gets the user info.
   *
   * @param accessToken the bearer token to use to authenticate for this call.
   * @return OAuth UserInfo model
   * @throws ApiException if the HTTP call status is different than 2xx.
   * @see OAuth.UserInfo
   */
  public OAuth.UserInfo getUserInfo(String accessToken)
      throws IllegalArgumentException, ApiException, IOException {
    if (accessToken == null || "".equals(accessToken)) {
      throw new IllegalArgumentException(
          "Cannot find a valid access token. Make sure OAuth is configured before you try again.");
    }

    CloseableHttpClient client = buildHttpClient(debugging);

    HttpGet request = new HttpGet("https://" + getOAuthBasePath() + "/oauth/userinfo");
    request.setHeader("Authorization", "Bearer " + accessToken);
    request.setHeader("Cache-Control", "no-store");
    request.setHeader("Pragma", "no-cache");

    CloseableHttpResponse response = null;

    try {
      response = client.execute(request);

      if (!isSuccessful(response)) {
        throw createException(response);
      }

      GenericType<OAuth.UserInfo> returnType = new GenericType<OAuth.UserInfo>() {};
      return deserialize(response, returnType);
    } finally {
      try {
        if (response != null) {
          response.close();
        }
      } catch (Exception e) {
        // it's not critical, since the response object is local in method invokeAPI; that's fine,
        // just continue
      }
    }
  }

  /**
   * Configures a listener which is notified when a new access token is received.
   *
   * @param accessTokenListener access token listener
   */
  public void registerAccessTokenListener(AccessTokenListener accessTokenListener) {
    for (Authentication auth : authentications.values()) {
      if (auth instanceof OAuth) {
        OAuth oauth = (OAuth) auth;
        oauth.registerAccessTokenListener(accessTokenListener);
        return;
      }
    }
  }

  /**
   * Helper method to build the OAuth JWT grant uri (used once to get a user consent for
   * impersonation).
   *
   * @param clientId OAuth2 client ID
   * @param redirectURI OAuth2 redirect uri
   * @return the OAuth JWT grant uri as a String
   */
  public String getJWTUri(String clientId, String redirectURI, String oAuthBasePath)
      throws URISyntaxException {
    return UriBuilder.fromUri(oAuthBasePath)
        .scheme("https")
        .path("/oauth/auth")
        .queryParam("response_type", "code")
        .queryParam("scope", "signature%20impersonation")
        .queryParam("client_id", clientId)
        .queryParam("redirect_uri", redirectURI)
        .build()
        .toString();
  }

  /**
   * Configures the current instance of ApiClient with a fresh OAuth JWT access token from DocuSign.
   *
   * @param clientId DocuSign OAuth Client Id (AKA Integrator Key)
   * @param userId DocuSign user Id to be impersonated (This is a UUID)
   * @param scopes the list of requested scopes. Values include {@link OAuth#Scope_SIGNATURE},
   *     {@link OAuth#Scope_EXTENDED}, {@link OAuth#Scope_IMPERSONATION}. You can also pass any
   *     advanced scope.
   * @param rsaPrivateKey the byte contents of the RSA private key
   * @param expiresIn number of seconds remaining before the JWT assertion is considered as invalid
   * @return OAuth.OAuthToken object.
   * @throws IllegalArgumentException if one of the arguments is invalid
   * @throws ApiException if there is an error while exchanging the JWT with an access token
   * @throws IOException if there is an issue with either the public or private file
   */
  public OAuth.OAuthToken requestJWTUserToken(
      String clientId,
      String userId,
      java.util.List<String> scopes,
      byte[] rsaPrivateKey,
      long expiresIn)
      throws IllegalArgumentException, ApiException, IOException {
    String formattedScopes = (scopes == null || scopes.size() < 1) ? "" : scopes.get(0);
    StringBuilder sb = new StringBuilder(formattedScopes);
    for (int i = 1; i < scopes.size(); i++) {
      sb.append(" " + scopes.get(i));
    }

    String assertion =
        JWTUtils.generateJWTAssertionFromByteArray(
            rsaPrivateKey, getOAuthBasePath(), clientId, userId, expiresIn, sb.toString());
    java.util.Map<String, Object> form = new java.util.HashMap<>();
    form.put("assertion", assertion);
    form.put("grant_type", OAuth.GRANT_TYPE_JWT);

    CloseableHttpClient client = buildHttpClient(debugging);

    HttpPost request = new HttpPost("https://" + getOAuthBasePath() + "/oauth/token");
    request.setHeader("Cache-Control", "no-store");
    request.setHeader("Pragma", "no-cache");

    HttpEntity entity =
        serialize(null, form, ContentType.APPLICATION_FORM_URLENCODED.getMimeType());
    request.setEntity(entity);
    CloseableHttpResponse response = null;

    try {
      response = client.execute(request);

      if (!isSuccessful(response)) {
        throw createException(response);
      }

      GenericType<OAuth.OAuthToken> returnType = new GenericType<OAuth.OAuthToken>() {};
      OAuth.OAuthToken oAuthToken = deserialize(response, returnType);
      if (oAuthToken.getAccessToken() == null
          || "".equals(oAuthToken.getAccessToken())
          || oAuthToken.getExpiresIn() <= 0) {
        throw new ApiException("Error while requesting an access token: " + response.toString());
      }
      return oAuthToken;
    } finally {
      try {
        if (response != null) {
          response.close();
        }
      } catch (Exception e) {
        // it's not critical, since the response object is local in method invokeAPI; that's fine,
        // just continue
      }
    }
  }

  /**
   * <b>RESERVED FOR PARTNERS</b> Request JWT Application Token. Configures the current instance of
   * ApiClient with a fresh OAuth JWT access token from DocuSign
   *
   * @param clientId DocuSign OAuth Client Id (AKA Integrator Key)
   * @param scopes the list of requested scopes. Values include {@link OAuth#Scope_SIGNATURE},
   *     {@link OAuth#Scope_EXTENDED}, {@link OAuth#Scope_IMPERSONATION}. You can also pass any
   *     advanced scope.
   * @param rsaPrivateKey the byte contents of the RSA private key
   * @param expiresIn number of seconds remaining before the JWT assertion is considered as invalid
   * @return OAuth.OAuthToken object.
   * @throws IllegalArgumentException if one of the arguments is invalid
   * @throws IOException if there is an issue with either the public or private file
   * @throws ApiException if there is an error while exchanging the JWT with an access token
   */
  public OAuth.OAuthToken requestJWTApplicationToken(
      String clientId, java.util.List<String> scopes, byte[] rsaPrivateKey, long expiresIn)
      throws IllegalArgumentException, IOException, ApiException {
    return this.requestJWTUserToken(clientId, null, scopes, rsaPrivateKey, expiresIn);
  }

  /**
   * Parse the given string into Date object.
   *
   * @param str String
   * @return Date
   */
  public Date parseDate(String str) {
    try {
      return dateFormat.parse(str);
    } catch (java.text.ParseException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Format the given Date object into string.
   *
   * @param date Date
   * @return Date in string format
   */
  public String formatDate(Date date) {
    return dateFormat.format(date);
  }

  /**
   * Format the given parameter object into string.
   *
   * @param param Object
   * @return Object in string format
   */
  public String parameterToString(Object param) {
    if (param == null) {
      return "";
    } else if (param instanceof Date) {
      return formatDate((Date) param);
    } else if (param instanceof Collection) {
      StringBuilder b = new StringBuilder();
      for (Object o : (Collection) param) {
        if (b.length() > 0) {
          b.append(',');
        }
        b.append(String.valueOf(o));
      }
      return b.toString();
    } else {
      return String.valueOf(param);
    }
  }

  /**
   * Formats the specified query parameter to a list containing a single {@code Pair} object.
   *
   * <p>Note that {@code value} must not be a collection.
   *
   * @param name The name of the parameter.
   * @param value The value of the parameter.
   * @return A list containing a single {@code Pair} object.
   */
  public List<Pair> parameterToPair(String name, Object value) {
    List<Pair> params = new ArrayList<Pair>();

    // preconditions
    if (name == null || name.isEmpty() || value == null || value instanceof Collection) {
      return params;
    }

    params.add(new Pair(name, parameterToString(value)));
    return params;
  }

  /**
   * Formats the specified collection query parameters to a list of {@code Pair} objects.
   *
   * <p>Note that the values of each of the returned Pair objects are percent-encoded.
   *
   * @param collectionFormat The collection format of the parameter.
   * @param name The name of the parameter.
   * @param value The value of the parameter.
   * @return A list of {@code Pair} objects.
   */
  public List<Pair> parameterToPairs(String collectionFormat, String name, Collection value) {
    List<Pair> params = new ArrayList<Pair>();

    // preconditions
    if (name == null || name.isEmpty() || value == null) {
      return params;
    }

    // create the params based on the collection format
    if ("multi".equals(collectionFormat)) {
      for (Object item : value) {
        params.add(new Pair(name, escapeString(parameterToString(item))));
      }
      return params;
    }

    // collectionFormat is assumed to be "csv" by default
    String delimiter = ",";

    // escape all delimiters except commas, which are URI reserved
    // characters
    if ("ssv".equals(collectionFormat)) {
      delimiter = escapeString(" ");
    } else if ("tsv".equals(collectionFormat)) {
      delimiter = escapeString("\t");
    } else if ("pipes".equals(collectionFormat)) {
      delimiter = escapeString("|");
    }

    StringBuilder sb = new StringBuilder();
    for (Object item : value) {
      sb.append(delimiter);
      sb.append(escapeString(parameterToString(item)));
    }

    params.add(new Pair(name, sb.substring(delimiter.length())));

    return params;
  }

  /**
   * Format to {@code Pair} objects.
   *
   * @param collectionFormat Collection format
   * @param name Name
   * @param value Value
   * @return List of pairs
   */
  public List<Pair> parameterToPairs(String collectionFormat, String name, Object value) {
    List<Pair> params = new ArrayList<Pair>();

    // preconditions
    if (name == null || name.isEmpty() || value == null) {
      return params;
    }

    Collection valueCollection;
    if (value instanceof Collection) {
      valueCollection = (Collection) value;
    } else {
      params.add(new Pair(name, parameterToString(value)));
      return params;
    }

    if (valueCollection.isEmpty()) {
      return params;
    }

    // get the collection format (default: csv)
    String format =
        (collectionFormat == null || collectionFormat.isEmpty() ? "csv" : collectionFormat);

    // create the params based on the collection format
    if ("multi".equals(format)) {
      for (Object item : valueCollection) {
        params.add(new Pair(name, parameterToString(item)));
      }

      return params;
    }

    String delimiter = ",";

    if ("csv".equals(format)) {
      delimiter = ",";
    } else if ("ssv".equals(format)) {
      delimiter = " ";
    } else if ("tsv".equals(format)) {
      delimiter = "\t";
    } else if ("pipes".equals(format)) {
      delimiter = "|";
    }

    StringBuilder sb = new StringBuilder();
    for (Object item : valueCollection) {
      sb.append(delimiter);
      sb.append(parameterToString(item));
    }

    params.add(new Pair(name, sb.substring(1)));

    return params;
  }

  /**
   * Check if the given MIME is a JSON MIME. JSON MIME examples: application/json application/json;
   * charset=UTF8 APPLICATION/JSON application/vnd.company+json "* / *" is also default to JSON
   *
   * @param mime MIME
   * @return True if the MIME type is JSON
   */
  public boolean isJsonMime(String mime) {
    String jsonMime = "(?i)^(application/json|[^;/ \t]+/[^;/ \t]+[+]json)[ \t]*(;.*)?$";
    return mime != null && (mime.matches(jsonMime) || mime.equals("*/*"));
  }

  /**
   * Select the Accept header's value from the given accepts array: if JSON exists in the given
   * array, use it; otherwise use all of them (joining into a string).
   *
   * @param accepts The accepts array to select from
   * @return The Accept header to use. If the given array is empty, null will be returned (not to
   *     set the Accept header explicitly).
   */
  public String selectHeaderAccept(String[] accepts) {
    if (accepts.length == 0) {
      return null;
    }
    for (String accept : accepts) {
      if (isJsonMime(accept)) {
        return accept;
      }
    }
    return StringUtil.join(accepts, ",");
  }

  /**
   * Select the Content-Type header's value from the given array. if JSON exists in the given array,
   * use it; otherwise use the first one of the array.
   *
   * @param contentTypes The Content-Type array to select from
   * @return The Content-Type header to use. If the given array is empty, JSON will be used.
   */
  public String selectHeaderContentType(String[] contentTypes) {
    if (contentTypes.length == 0 || contentTypes[0].equals("*/*")) {
      return "application/json";
    }
    for (String contentType : contentTypes) {
      if (isJsonMime(contentType)) {
        return contentType;
      }
    }
    return contentTypes[0];
  }

  /**
   * Escape the given string to be used as URL query value.
   *
   * @param str String
   * @return Escaped string
   */
  public String escapeString(String str) {
    try {
      return URLEncoder.encode(str, "utf8").replaceAll("\\+", "%20");
    } catch (UnsupportedEncodingException e) {
      return str;
    }
  }

  /**
   * Serialize the given Java object into string entity according the given Content-Type (only JSON
   * is supported for now).
   *
   * @param obj Object
   * @param formParams Form parameters
   * @param contentType Context type
   * @return Entity
   * @throws ApiException API exception
   */
  public HttpEntity serialize(Object obj, Map<String, Object> formParams, String contentType)
      throws ApiException {
    EntityBuilder b = EntityBuilder.create();
    if (contentType.startsWith("multipart/form-data")) {
      MultipartEntityBuilder mb = MultipartEntityBuilder.create();
      for (Entry<String, Object> param : formParams.entrySet()) {
        if (param.getValue() instanceof byte[]) {
          byte[] bytes = (byte[]) param.getValue();
          mb.addBinaryBody(param.getKey(), bytes);
        } else if (param.getValue() instanceof File) {
          File file = (File) param.getValue();
          mb.addBinaryBody(param.getKey(), file);
        } else {
          mb.addTextBody(param.getKey(), parameterToString(param.getValue()));
        }
      }
      return mb.build();
    } else if (contentType.startsWith("application/x-www-form-urlencoded")) {
      List<NameValuePair> parameters = new ArrayList<>();
      for (Entry<String, Object> param : formParams.entrySet()) {
        parameters.add(
            LocalNameValuePair.create(param.getKey(), parameterToString(param.getValue())));
      }
      b.setParameters(parameters);
      b.setContentType(ContentType.APPLICATION_FORM_URLENCODED);
    } else if (contentType.startsWith("text/csv")) {
      return this.serializeToCsv(obj);
    } else {
        StringEntity requestEntity = new StringEntity(
    toJson(obj),
    ContentType.APPLICATION_JSON);
        return requestEntity;
      //b.setContentType(ContentType.create(contentType)).setText(toJson(obj));
    }
    return b.build();
  }

  private <T> T parseJson(HttpEntity e, GenericType<T> genericType) throws ApiException {
    try {
      return (T) getObjectMapper().readValue(e.getContent(), genericType.getRawType());
    } catch (IOException ex) {
      throw new ApiException(ex);
    }
  }

  private String toJson(Object obj) throws ApiException {
    try {
      return getObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(obj);
    } catch (Exception ex) {
      throw new ApiException(ex);
    }
  }

  /**
   * Deserialize response body to Java object according to the Content-Type.
   *
   * @param <T> Type
   * @param response Response
   * @param returnType Return type
   * @return Deserialize object
   * @throws ApiException API exception
   */
  @SuppressWarnings("unchecked")
  public <T> T deserialize(CloseableHttpResponse response, GenericType<T> returnType)
      throws ApiException {
    if (response == null || returnType == null || response.getEntity() == null) {
      return null;
    }
    
    if ("byte[]".equals(returnType.getType().getTypeName())) {
      try {
        // Handle binary response (byte array).
        return (T) response.getEntity().getContent().readAllBytes();
      } catch (Exception ex) {
        throw new ApiException(ex);
      }
    } else if (returnType.getRawType() == File.class) {
      // Handle file downloading.
      T file = (T) downloadFileFromResponse(response);
      return file;
    }

    String contentType = null;
    Header[] headers = response.getHeaders("Content-Type");
    if (headers != null && headers.length > 0) {
      contentType = String.valueOf(headers[0].getValue());
    }

    return parseJson(response.getEntity(), returnType);
  }

  /**
   * Download file from the given response.
   *
   * @param response Response
   * @return File
   * @throws ApiException If fail to read file content from response and write to disk
   */
  public File downloadFileFromResponse(CloseableHttpResponse response) throws ApiException {
    try {
      File file = prepareDownloadFile(response);
      Files.copy(
          response.getEntity().getContent(), file.toPath(), StandardCopyOption.REPLACE_EXISTING);
      return file;
    } catch (IOException e) {
      throw new ApiException(e);
    }
  }

  /**
   * Prepare to downloand file.
   *
   * @param response Response
   * @return File
   * @throws ApiException If fail to read file content from response and write to disk
   */
  public File prepareDownloadFile(CloseableHttpResponse response) throws IOException {
    String filename = null;
    Header[] headers = response.getHeaders("Content-Disposition");
    if (headers != null && headers.length > 0) {
      String contentDisposition = headers[0].getValue();
      // Get filename from the Content-Disposition header.
      Pattern pattern = Pattern.compile("filename=['\"]?([^'\"\\s]+)['\"]?");
      Matcher matcher = pattern.matcher(contentDisposition);
      if (matcher.find()) {
        filename = matcher.group(1);
      }
    }

    String prefix;
    String suffix = null;
    if (filename == null) {
      prefix = "download-";
      suffix = "";
    } else {
      int pos = filename.lastIndexOf('.');
      if (pos == -1) {
        prefix = filename + "-";
      } else {
        prefix = filename.substring(0, pos) + "-";
        suffix = filename.substring(pos);
      }
      // File.createTempFile requires the prefix to be at least three characters long
      if (prefix.length() < 3) {
        prefix = "download-";
      }
    }

    if (tempFolderPath == null) {
      return File.createTempFile(prefix, suffix);
    } else {
      return File.createTempFile(prefix, suffix, new File(tempFolderPath));
    }
  }

  /**
   * Invoke API by sending HTTP request with the given options.
   *
   * @param <T> Type
   * @param path The sub-path of the HTTP URL
   * @param method The request method, one of "GET", "POST", "PUT", "HEAD" and "DELETE"
   * @param queryParams The query parameters
   * @param collectionQueryParams The collection query parameters
   * @param body The request body object
   * @param headerParams The header parameters
   * @param formParams The form parameters
   * @param accept The request's Accept header
   * @param contentType The request's Content-Type header
   * @param authNames The authentications to apply
   * @param returnType The return type into which to deserialize the response
   * @return The response body in type of string
   * @throws ApiException API exception
   */
  public <T> T invokeAPI(
      String path,
      String method,
      List<Pair> queryParams,
      List<Pair> collectionQueryParams,
      Object body,
      Map<String, String> headerParams,
      Map<String, Object> formParams,
      String accept,
      String contentType,
      String[] authNames,
      GenericType<T> returnType)
      throws ApiException {
    updateParamsForAuth(authNames, queryParams, headerParams);

    CloseableHttpClient client = buildHttpClient(debugging);
    List<Header> headers = new ArrayList<>();
    UriBuilder b = null;
    try {
      b = UriBuilder.fromUri(this.basePath + path);
    } catch (URISyntaxException ex) {
      throw new ApiException(ex);
    }

    // Not using `.target(this.basePath).path(path)` below,
    // to support (constant) query string in `path`, e.g. "/posts?draft=1"
    // WebTarget target = httpClient.target(this.basePath + path);
    if (queryParams != null) {
      for (Pair queryParam : queryParams) {
        if (queryParam.getValue() != null) {
          b.queryParam(queryParam.getName(), queryParam.getValue());
        }
      }
    }

    if (collectionQueryParams != null) {
      for (Pair param : collectionQueryParams) {
        if (param.getValue() != null) {
          headers.add(new BasicHeader(param.getName(), param.getValue()));
        }
      }
    }

    headers.add(new BasicHeader("Accept", accept));

    for (Entry<String, String> entry : headerParams.entrySet()) {
      String value = entry.getValue();
      if (value != null) {
        headers.add(new BasicHeader(entry.getKey(), value));
      }
    }

    for (Entry<String, String> entry : defaultHeaderMap.entrySet()) {
      String key = entry.getKey();
      if (!headerParams.containsKey(key)) {
        String value = entry.getValue();
        if (value != null) {
          headers.add(new BasicHeader(key, value));
        }
      }
    }

    HttpEntity entity =
        (body == null && formParams.isEmpty())
            ? EntityBuilder.create()
                .setText("{}")
                .setContentType(ContentType.APPLICATION_JSON)
                .build()
            : serialize(body, formParams, contentType);

    // Generate and add Content-Disposition header as per RFC 6266
    if (contentType.startsWith("multipart/form-data")) {
        //TODO
        throw new IllegalArgumentException("Unimplemented");
    }

    // Add DocuSign Tracking Header
    headers.add(new BasicHeader("X-DocuSign-SDK", "Java"));

    if (body == null && formParams.isEmpty()) {
      headers.add(new BasicHeader("Content-Length", "0"));
    }

    CloseableHttpResponse response = null;
    String message = "error";
    String respBody = null;

    try {
      HttpRequestBase request = null;
      if ("GET".equals(method)) {
        request = new HttpGet(b.build());
      } else if ("POST".equals(method)) {
        request = new HttpPost(b.build());
      } else if ("PUT".equals(method)) {
        request = new HttpPut(b.build());
      } else if ("DELETE".equals(method)) {
        request = new HttpDelete(b.build());
      } else if ("PATCH".equals(method)) {
        request = new HttpPatch(b.build());
      } else if ("HEAD".equals(method)) {
        request = new HttpHead(b.build());
      } else {
        throw new ApiException(500, "unknown method type " + method);
      }

      for (Header header : headers) {
        request.addHeader(header);
      }

      if(request instanceof HttpEntityEnclosingRequestBase){
          HttpEntityEnclosingRequestBase erequest = (HttpEntityEnclosingRequestBase) request;
          erequest.setEntity(entity);
      }
      
      response = client.execute(request);

      statusCode = response.getStatusLine().getStatusCode();
      responseHeaders = buildResponseHeaders(response);

      if (!isSuccessful(response)) {
        throw createException(response);
      }

      if (response.getStatusLine().getStatusCode() == HttpStatus.SC_NO_CONTENT) {
        return null;
      } else if (isSuccessful(response)) {
        if (returnType == null) {
          return null;
        } else {
          return deserialize(response, returnType);
        }
      } else {
        if (response.getEntity() != null) {
          try {
            respBody = new String(response.getEntity().getContent().readAllBytes());
            message = respBody;
          } catch (Exception e) {
            // e.printStackTrace();
          }
        }
        throw new ApiException(statusCode, message, buildResponseHeaders(response), respBody);
      }
    } catch (Exception ex) {
      throw new ApiException(ex);
    } finally {
      try {
        response.close();
      } catch (Exception e) {
        // it's not critical, since the response object is local in method invokeAPI; that's fine,
        // just continue
      }
    }
  }

  /**
   * Encode the given form parameters as request body.
   *
   * @param formParams Form parameters
   * @return HTTP form encoded parameters
   */
  private String getXWWWFormUrlencodedParams(Map<String, Object> formParams) {
    StringBuilder formParamBuilder = new StringBuilder();

    for (Entry<String, Object> param : formParams.entrySet()) {
      String valueStr = parameterToString(param.getValue());
      try {
        formParamBuilder
            .append(URLEncoder.encode(param.getKey(), "utf8"))
            .append("=")
            .append(URLEncoder.encode(valueStr, "utf8"));
        formParamBuilder.append("&");
      } catch (UnsupportedEncodingException e) {
        // move on to next
      }
    }

    String encodedFormParams = formParamBuilder.toString();
    if (encodedFormParams.endsWith("&")) {
      encodedFormParams = encodedFormParams.substring(0, encodedFormParams.length() - 1);
    }

    return encodedFormParams;
  }

  /** Encode the given request object in CSV format. */
  private HttpEntity serializeToCsv(Object obj) {
    if (obj == null) {
      return EntityBuilder.create().setText("").build();
    } else if (obj.getClass() == byte[].class) {
      return EntityBuilder.create()
          .setBinary((byte[]) obj)
          .setContentType(ContentType.create("text/csv"))
          .build();
    }

    for (Method method : obj.getClass().getMethods()) {
      if ("java.util.List".equals(method.getReturnType().getName())) {
        try {
          @SuppressWarnings("rawtypes")
          java.util.List itemList = (java.util.List) method.invoke(obj);
          Object entry = itemList.get(0);

          List<String> stringList = new ArrayList<String>();
          char delimiter = ',';
          String lineSep = "\n";

          CsvMapper mapper = new CsvMapper();
          mapper.enable(JsonGenerator.Feature.IGNORE_UNKNOWN);
          CsvSchema schema = mapper.schemaFor(entry.getClass());
          for (int i = 0; i < itemList.size(); i++) {
            if (i == 0) {
              schema = schema.withHeader();
            } else {
              schema = schema.withoutHeader();
            }
            String csv =
                mapper
                    .writer(
                        schema
                            .withColumnSeparator(delimiter)
                            .withoutQuoteChar()
                            .withLineSeparator(lineSep))
                    .writeValueAsString(itemList.get(i));

            stringList.add(csv);
          }
          return EntityBuilder.create()
              .setText(StringUtil.join(stringList.toArray(new String[0]), ""))
              .setContentType(ContentType.create("text/csv"))
              .build();
        } catch (JsonProcessingException e) {
          System.out.println(e);
        } catch (IllegalAccessException e) {
          System.out.println(e);
        } catch (IllegalArgumentException e) {
          System.out.println(e);
        } catch (InvocationTargetException e) {
          System.out.println(e);
        }
      }
    }
    return EntityBuilder.create()
        .setText("")
        .setContentType(ContentType.create("text/csv"))
        .build();
  }

  /**
   * Build the Client used to make HTTP requests.
   *
   * @param debugging Debug setting
   * @return Client
   */
  protected CloseableHttpClient buildHttpClient(boolean debugging) {
    return HttpClients.custom().setDefaultRequestConfig(config).build();
  }

  protected Map<String, List<String>> buildResponseHeaders(CloseableHttpResponse response) {
    Map<String, List<String>> responseHeaders = new HashMap<String, List<String>>();

    for (Header header : response.getAllHeaders()) {
      responseHeaders.put(header.getName(), Arrays.asList(String.valueOf(header.getValue())));
    }

    return responseHeaders;
  }

  /**
   * Update query and header parameters based on authentication settings.
   *
   * @param authNames The authentications to apply
   */
  protected void updateParamsForAuth(
      String[] authNames, List<Pair> queryParams, Map<String, String> headerParams) {
    for (String authName : authNames) {
      Authentication auth = authentications.get(authName);
      if (auth == null) {
        throw new RuntimeException("Authentication undefined: " + authName);
      }
      auth.applyToParams(queryParams, headerParams);
    }
  }
}
