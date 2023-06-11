package com.docusign.esign.model;

import com.docusign.esign.override.swagger.Schema;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;

/** UserAuthorizationCreateRequestWithId. */
public class UserAuthorizationCreateRequestWithId {
  @JsonProperty("agentUser")
  private AuthorizationUser agentUser = null;

  @JsonProperty("authorizationId")
  private String authorizationId = null;

  @JsonProperty("endDate")
  private String endDate = null;

  @JsonProperty("permission")
  private String permission = null;

  @JsonProperty("startDate")
  private String startDate = null;

  /**
   * agentUser.
   *
   * @return UserAuthorizationCreateRequestWithId
   */
  public UserAuthorizationCreateRequestWithId agentUser(AuthorizationUser agentUser) {
    this.agentUser = agentUser;
    return this;
  }

  /**
   * .
   *
   * @return agentUser
   */
  @Schema(description = "")
  public AuthorizationUser getAgentUser() {
    return agentUser;
  }

  /** setAgentUser. */
  public void setAgentUser(AuthorizationUser agentUser) {
    this.agentUser = agentUser;
  }

  /**
   * authorizationId.
   *
   * @return UserAuthorizationCreateRequestWithId
   */
  public UserAuthorizationCreateRequestWithId authorizationId(String authorizationId) {
    this.authorizationId = authorizationId;
    return this;
  }

  /**
   * .
   *
   * @return authorizationId
   */
  @Schema(description = "")
  public String getAuthorizationId() {
    return authorizationId;
  }

  /** setAuthorizationId. */
  public void setAuthorizationId(String authorizationId) {
    this.authorizationId = authorizationId;
  }

  /**
   * endDate.
   *
   * @return UserAuthorizationCreateRequestWithId
   */
  public UserAuthorizationCreateRequestWithId endDate(String endDate) {
    this.endDate = endDate;
    return this;
  }

  /**
   * .
   *
   * @return endDate
   */
  @Schema(description = "")
  public String getEndDate() {
    return endDate;
  }

  /** setEndDate. */
  public void setEndDate(String endDate) {
    this.endDate = endDate;
  }

  /**
   * permission.
   *
   * @return UserAuthorizationCreateRequestWithId
   */
  public UserAuthorizationCreateRequestWithId permission(String permission) {
    this.permission = permission;
    return this;
  }

  /**
   * .
   *
   * @return permission
   */
  @Schema(description = "")
  public String getPermission() {
    return permission;
  }

  /** setPermission. */
  public void setPermission(String permission) {
    this.permission = permission;
  }

  /**
   * startDate.
   *
   * @return UserAuthorizationCreateRequestWithId
   */
  public UserAuthorizationCreateRequestWithId startDate(String startDate) {
    this.startDate = startDate;
    return this;
  }

  /**
   * .
   *
   * @return startDate
   */
  @Schema(description = "")
  public String getStartDate() {
    return startDate;
  }

  /** setStartDate. */
  public void setStartDate(String startDate) {
    this.startDate = startDate;
  }

  /**
   * Compares objects.
   *
   * @return true or false depending on comparison result.
   */
  @Override
  public boolean equals(java.lang.Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    UserAuthorizationCreateRequestWithId userAuthorizationCreateRequestWithId =
        (UserAuthorizationCreateRequestWithId) o;
    return Objects.equals(this.agentUser, userAuthorizationCreateRequestWithId.agentUser)
        && Objects.equals(
            this.authorizationId, userAuthorizationCreateRequestWithId.authorizationId)
        && Objects.equals(this.endDate, userAuthorizationCreateRequestWithId.endDate)
        && Objects.equals(this.permission, userAuthorizationCreateRequestWithId.permission)
        && Objects.equals(this.startDate, userAuthorizationCreateRequestWithId.startDate);
  }

  /** Returns the HashCode. */
  @Override
  public int hashCode() {
    return Objects.hash(agentUser, authorizationId, endDate, permission, startDate);
  }

  /** Converts the given object to string. */
  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class UserAuthorizationCreateRequestWithId {\n");

    sb.append("    agentUser: ").append(toIndentedString(agentUser)).append("\n");
    sb.append("    authorizationId: ").append(toIndentedString(authorizationId)).append("\n");
    sb.append("    endDate: ").append(toIndentedString(endDate)).append("\n");
    sb.append("    permission: ").append(toIndentedString(permission)).append("\n");
    sb.append("    startDate: ").append(toIndentedString(startDate)).append("\n");
    sb.append("}");
    return sb.toString();
  }

  /**
   * Convert the given object to string with each line indented by 4 spaces (except the first line).
   */
  private String toIndentedString(java.lang.Object o) {
    if (o == null) {
      return "null";
    }
    return o.toString().replace("\n", "\n    ");
  }
}
