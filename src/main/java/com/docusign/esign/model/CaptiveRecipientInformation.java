package com.docusign.esign.model;

import com.docusign.esign.override.swagger.Schema;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;

/** Contains information about captive (embedded) recipients.. */
@Schema(description = "Contains information about captive (embedded) recipients.")
public class CaptiveRecipientInformation {
  @JsonProperty("captiveRecipients")
  private java.util.List<CaptiveRecipient> captiveRecipients = null;

  /**
   * captiveRecipients.
   *
   * @return CaptiveRecipientInformation
   */
  public CaptiveRecipientInformation captiveRecipients(
      java.util.List<CaptiveRecipient> captiveRecipients) {
    this.captiveRecipients = captiveRecipients;
    return this;
  }

  /**
   * addCaptiveRecipientsItem.
   *
   * @return CaptiveRecipientInformation
   */
  public CaptiveRecipientInformation addCaptiveRecipientsItem(
      CaptiveRecipient captiveRecipientsItem) {
    if (this.captiveRecipients == null) {
      this.captiveRecipients = new java.util.ArrayList<>();
    }
    this.captiveRecipients.add(captiveRecipientsItem);
    return this;
  }

  /**
   * A complex type containing information about one or more captive recipients..
   *
   * @return captiveRecipients
   */
  @Schema(
      description = "A complex type containing information about one or more captive recipients.")
  public java.util.List<CaptiveRecipient> getCaptiveRecipients() {
    return captiveRecipients;
  }

  /** setCaptiveRecipients. */
  public void setCaptiveRecipients(java.util.List<CaptiveRecipient> captiveRecipients) {
    this.captiveRecipients = captiveRecipients;
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
    CaptiveRecipientInformation captiveRecipientInformation = (CaptiveRecipientInformation) o;
    return Objects.equals(this.captiveRecipients, captiveRecipientInformation.captiveRecipients);
  }

  /** Returns the HashCode. */
  @Override
  public int hashCode() {
    return Objects.hash(captiveRecipients);
  }

  /** Converts the given object to string. */
  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class CaptiveRecipientInformation {\n");

    sb.append("    captiveRecipients: ").append(toIndentedString(captiveRecipients)).append("\n");
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
