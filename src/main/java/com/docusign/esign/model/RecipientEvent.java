package com.docusign.esign.model;

import com.docusign.esign.override.swagger.Schema;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;

/** RecipientEvent. */
public class RecipientEvent {
  @JsonProperty("includeDocuments")
  private String includeDocuments = null;

  @JsonProperty("recipientEventStatusCode")
  private String recipientEventStatusCode = null;

  /**
   * includeDocuments.
   *
   * @return RecipientEvent
   */
  public RecipientEvent includeDocuments(String includeDocuments) {
    this.includeDocuments = includeDocuments;
    return this;
  }

  /**
   * When set to **true**, the PDF documents are included in the message along with the updated XML.
   * .
   *
   * @return includeDocuments
   */
  @Schema(
      description =
          "When set to **true**, the PDF documents are included in the message along with the updated XML. ")
  public String getIncludeDocuments() {
    return includeDocuments;
  }

  /** setIncludeDocuments. */
  public void setIncludeDocuments(String includeDocuments) {
    this.includeDocuments = includeDocuments;
  }

  /**
   * recipientEventStatusCode.
   *
   * @return RecipientEvent
   */
  public RecipientEvent recipientEventStatusCode(String recipientEventStatusCode) {
    this.recipientEventStatusCode = recipientEventStatusCode;
    return this;
  }

  /**
   * The recipient status, this can be Sent, Delivered, Completed, Declined, AuthenticationFailed,
   * and AutoResponded..
   *
   * @return recipientEventStatusCode
   */
  @Schema(
      description =
          "The recipient status, this can be Sent, Delivered, Completed, Declined, AuthenticationFailed, and AutoResponded.")
  public String getRecipientEventStatusCode() {
    return recipientEventStatusCode;
  }

  /** setRecipientEventStatusCode. */
  public void setRecipientEventStatusCode(String recipientEventStatusCode) {
    this.recipientEventStatusCode = recipientEventStatusCode;
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
    RecipientEvent recipientEvent = (RecipientEvent) o;
    return Objects.equals(this.includeDocuments, recipientEvent.includeDocuments)
        && Objects.equals(this.recipientEventStatusCode, recipientEvent.recipientEventStatusCode);
  }

  /** Returns the HashCode. */
  @Override
  public int hashCode() {
    return Objects.hash(includeDocuments, recipientEventStatusCode);
  }

  /** Converts the given object to string. */
  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class RecipientEvent {\n");

    sb.append("    includeDocuments: ").append(toIndentedString(includeDocuments)).append("\n");
    sb.append("    recipientEventStatusCode: ")
        .append(toIndentedString(recipientEventStatusCode))
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
