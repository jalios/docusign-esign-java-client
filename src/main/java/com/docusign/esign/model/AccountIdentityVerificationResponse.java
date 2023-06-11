package com.docusign.esign.model;

import com.docusign.esign.override.swagger.Schema;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;

/** AccountIdentityVerificationResponse. */
public class AccountIdentityVerificationResponse {
  @JsonProperty("identityVerification")
  private java.util.List<AccountIdentityVerificationWorkflow> identityVerification = null;

  /**
   * identityVerification.
   *
   * @return AccountIdentityVerificationResponse
   */
  public AccountIdentityVerificationResponse identityVerification(
      java.util.List<AccountIdentityVerificationWorkflow> identityVerification) {
    this.identityVerification = identityVerification;
    return this;
  }

  /**
   * addIdentityVerificationItem.
   *
   * @return AccountIdentityVerificationResponse
   */
  public AccountIdentityVerificationResponse addIdentityVerificationItem(
      AccountIdentityVerificationWorkflow identityVerificationItem) {
    if (this.identityVerification == null) {
      this.identityVerification = new java.util.ArrayList<>();
    }
    this.identityVerification.add(identityVerificationItem);
    return this;
  }

  /**
   * .
   *
   * @return identityVerification
   */
  @Schema(description = "")
  public java.util.List<AccountIdentityVerificationWorkflow> getIdentityVerification() {
    return identityVerification;
  }

  /** setIdentityVerification. */
  public void setIdentityVerification(
      java.util.List<AccountIdentityVerificationWorkflow> identityVerification) {
    this.identityVerification = identityVerification;
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
    AccountIdentityVerificationResponse accountIdentityVerificationResponse =
        (AccountIdentityVerificationResponse) o;
    return Objects.equals(
        this.identityVerification, accountIdentityVerificationResponse.identityVerification);
  }

  /** Returns the HashCode. */
  @Override
  public int hashCode() {
    return Objects.hash(identityVerification);
  }

  /** Converts the given object to string. */
  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class AccountIdentityVerificationResponse {\n");

    sb.append("    identityVerification: ")
        .append(toIndentedString(identityVerification))
        .append("\n");
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
