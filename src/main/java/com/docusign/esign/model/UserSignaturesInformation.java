package com.docusign.esign.model;

import com.docusign.esign.override.swagger.Schema;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;

/** UserSignaturesInformation. */
public class UserSignaturesInformation {
  @JsonProperty("userSignatures")
  private java.util.List<UserSignature> userSignatures = null;

  /**
   * userSignatures.
   *
   * @return UserSignaturesInformation
   */
  public UserSignaturesInformation userSignatures(java.util.List<UserSignature> userSignatures) {
    this.userSignatures = userSignatures;
    return this;
  }

  /**
   * addUserSignaturesItem.
   *
   * @return UserSignaturesInformation
   */
  public UserSignaturesInformation addUserSignaturesItem(UserSignature userSignaturesItem) {
    if (this.userSignatures == null) {
      this.userSignatures = new java.util.ArrayList<>();
    }
    this.userSignatures.add(userSignaturesItem);
    return this;
  }

  /**
   * .
   *
   * @return userSignatures
   */
  @Schema(description = "")
  public java.util.List<UserSignature> getUserSignatures() {
    return userSignatures;
  }

  /** setUserSignatures. */
  public void setUserSignatures(java.util.List<UserSignature> userSignatures) {
    this.userSignatures = userSignatures;
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
    UserSignaturesInformation userSignaturesInformation = (UserSignaturesInformation) o;
    return Objects.equals(this.userSignatures, userSignaturesInformation.userSignatures);
  }

  /** Returns the HashCode. */
  @Override
  public int hashCode() {
    return Objects.hash(userSignatures);
  }

  /** Converts the given object to string. */
  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class UserSignaturesInformation {\n");

    sb.append("    userSignatures: ").append(toIndentedString(userSignatures)).append("\n");
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
