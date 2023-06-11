package com.docusign.esign.model;

import com.docusign.esign.override.swagger.Schema;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;

/** SigningGroupUsers. */
public class SigningGroupUsers {
  @JsonProperty("users")
  private java.util.List<SigningGroupUser> users = null;

  /**
   * users.
   *
   * @return SigningGroupUsers
   */
  public SigningGroupUsers users(java.util.List<SigningGroupUser> users) {
    this.users = users;
    return this;
  }

  /**
   * addUsersItem.
   *
   * @return SigningGroupUsers
   */
  public SigningGroupUsers addUsersItem(SigningGroupUser usersItem) {
    if (this.users == null) {
      this.users = new java.util.ArrayList<>();
    }
    this.users.add(usersItem);
    return this;
  }

  /**
   * .
   *
   * @return users
   */
  @Schema(description = "")
  public java.util.List<SigningGroupUser> getUsers() {
    return users;
  }

  /** setUsers. */
  public void setUsers(java.util.List<SigningGroupUser> users) {
    this.users = users;
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
    SigningGroupUsers signingGroupUsers = (SigningGroupUsers) o;
    return Objects.equals(this.users, signingGroupUsers.users);
  }

  /** Returns the HashCode. */
  @Override
  public int hashCode() {
    return Objects.hash(users);
  }

  /** Converts the given object to string. */
  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class SigningGroupUsers {\n");

    sb.append("    users: ").append(toIndentedString(users)).append("\n");
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
