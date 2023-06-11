package com.docusign.esign.model;

import com.docusign.esign.override.swagger.Schema;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;

/** ConsentDetails. */
public class ConsentDetails {
  @JsonProperty("consentKey")
  private String consentKey = null;

  @JsonProperty("deliveryMethod")
  private String deliveryMethod = null;

  @JsonProperty("signerConsentStatus")
  private String signerConsentStatus = null;

  /**
   * consentKey.
   *
   * @return ConsentDetails
   */
  public ConsentDetails consentKey(String consentKey) {
    this.consentKey = consentKey;
    return this;
  }

  /**
   * .
   *
   * @return consentKey
   */
  @Schema(description = "")
  public String getConsentKey() {
    return consentKey;
  }

  /** setConsentKey. */
  public void setConsentKey(String consentKey) {
    this.consentKey = consentKey;
  }

  /**
   * deliveryMethod.
   *
   * @return ConsentDetails
   */
  public ConsentDetails deliveryMethod(String deliveryMethod) {
    this.deliveryMethod = deliveryMethod;
    return this;
  }

  /**
   * Reserved: For DocuSign use only..
   *
   * @return deliveryMethod
   */
  @Schema(description = "Reserved: For DocuSign use only.")
  public String getDeliveryMethod() {
    return deliveryMethod;
  }

  /** setDeliveryMethod. */
  public void setDeliveryMethod(String deliveryMethod) {
    this.deliveryMethod = deliveryMethod;
  }

  /**
   * signerConsentStatus.
   *
   * @return ConsentDetails
   */
  public ConsentDetails signerConsentStatus(String signerConsentStatus) {
    this.signerConsentStatus = signerConsentStatus;
    return this;
  }

  /**
   * .
   *
   * @return signerConsentStatus
   */
  @Schema(description = "")
  public String getSignerConsentStatus() {
    return signerConsentStatus;
  }

  /** setSignerConsentStatus. */
  public void setSignerConsentStatus(String signerConsentStatus) {
    this.signerConsentStatus = signerConsentStatus;
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
    ConsentDetails consentDetails = (ConsentDetails) o;
    return Objects.equals(this.consentKey, consentDetails.consentKey)
        && Objects.equals(this.deliveryMethod, consentDetails.deliveryMethod)
        && Objects.equals(this.signerConsentStatus, consentDetails.signerConsentStatus);
  }

  /** Returns the HashCode. */
  @Override
  public int hashCode() {
    return Objects.hash(consentKey, deliveryMethod, signerConsentStatus);
  }

  /** Converts the given object to string. */
  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class ConsentDetails {\n");

    sb.append("    consentKey: ").append(toIndentedString(consentKey)).append("\n");
    sb.append("    deliveryMethod: ").append(toIndentedString(deliveryMethod)).append("\n");
    sb.append("    signerConsentStatus: ")
        .append(toIndentedString(signerConsentStatus))
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
