package com.docusign.esign.model;

import com.docusign.esign.override.swagger.Schema;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;

/** Defines a billing payments response object.. */
@Schema(description = "Defines a billing payments response object.")
public class BillingPaymentsResponse {
  @JsonProperty("billingPayments")
  private java.util.List<BillingPaymentItem> billingPayments = null;

  @JsonProperty("nextUri")
  private String nextUri = null;

  @JsonProperty("previousUri")
  private String previousUri = null;

  /**
   * billingPayments.
   *
   * @return BillingPaymentsResponse
   */
  public BillingPaymentsResponse billingPayments(
      java.util.List<BillingPaymentItem> billingPayments) {
    this.billingPayments = billingPayments;
    return this;
  }

  /**
   * addBillingPaymentsItem.
   *
   * @return BillingPaymentsResponse
   */
  public BillingPaymentsResponse addBillingPaymentsItem(BillingPaymentItem billingPaymentsItem) {
    if (this.billingPayments == null) {
      this.billingPayments = new java.util.ArrayList<>();
    }
    this.billingPayments.add(billingPaymentsItem);
    return this;
  }

  /**
   * Reserved: TBD.
   *
   * @return billingPayments
   */
  @Schema(description = "Reserved: TBD")
  public java.util.List<BillingPaymentItem> getBillingPayments() {
    return billingPayments;
  }

  /** setBillingPayments. */
  public void setBillingPayments(java.util.List<BillingPaymentItem> billingPayments) {
    this.billingPayments = billingPayments;
  }

  /**
   * nextUri.
   *
   * @return BillingPaymentsResponse
   */
  public BillingPaymentsResponse nextUri(String nextUri) {
    this.nextUri = nextUri;
    return this;
  }

  /**
   * The URI to the next chunk of records based on the search request. If the endPosition is the
   * entire results of the search, this is null. .
   *
   * @return nextUri
   */
  @Schema(
      description =
          "The URI to the next chunk of records based on the search request. If the endPosition is the entire results of the search, this is null. ")
  public String getNextUri() {
    return nextUri;
  }

  /** setNextUri. */
  public void setNextUri(String nextUri) {
    this.nextUri = nextUri;
  }

  /**
   * previousUri.
   *
   * @return BillingPaymentsResponse
   */
  public BillingPaymentsResponse previousUri(String previousUri) {
    this.previousUri = previousUri;
    return this;
  }

  /**
   * The postal code for the billing address..
   *
   * @return previousUri
   */
  @Schema(description = "The postal code for the billing address.")
  public String getPreviousUri() {
    return previousUri;
  }

  /** setPreviousUri. */
  public void setPreviousUri(String previousUri) {
    this.previousUri = previousUri;
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
    BillingPaymentsResponse billingPaymentsResponse = (BillingPaymentsResponse) o;
    return Objects.equals(this.billingPayments, billingPaymentsResponse.billingPayments)
        && Objects.equals(this.nextUri, billingPaymentsResponse.nextUri)
        && Objects.equals(this.previousUri, billingPaymentsResponse.previousUri);
  }

  /** Returns the HashCode. */
  @Override
  public int hashCode() {
    return Objects.hash(billingPayments, nextUri, previousUri);
  }

  /** Converts the given object to string. */
  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class BillingPaymentsResponse {\n");

    sb.append("    billingPayments: ").append(toIndentedString(billingPayments)).append("\n");
    sb.append("    nextUri: ").append(toIndentedString(nextUri)).append("\n");
    sb.append("    previousUri: ").append(toIndentedString(previousUri)).append("\n");
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
