package com.docusign.esign.model;

import com.docusign.esign.override.swagger.Schema;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;

/** BulkRecipientsResponse. */
public class BulkRecipientsResponse {
  @JsonProperty("bulkRecipients")
  private java.util.List<BulkRecipient> bulkRecipients = null;

  @JsonProperty("endPosition")
  private String endPosition = null;

  @JsonProperty("nextUri")
  private String nextUri = null;

  @JsonProperty("previousUri")
  private String previousUri = null;

  @JsonProperty("resultSetSize")
  private String resultSetSize = null;

  @JsonProperty("startPosition")
  private String startPosition = null;

  @JsonProperty("totalSetSize")
  private String totalSetSize = null;

  /**
   * bulkRecipients.
   *
   * @return BulkRecipientsResponse
   */
  public BulkRecipientsResponse bulkRecipients(java.util.List<BulkRecipient> bulkRecipients) {
    this.bulkRecipients = bulkRecipients;
    return this;
  }

  /**
   * addBulkRecipientsItem.
   *
   * @return BulkRecipientsResponse
   */
  public BulkRecipientsResponse addBulkRecipientsItem(BulkRecipient bulkRecipientsItem) {
    if (this.bulkRecipients == null) {
      this.bulkRecipients = new java.util.ArrayList<>();
    }
    this.bulkRecipients.add(bulkRecipientsItem);
    return this;
  }

  /**
   * A complex type containing information about the bulk recipients in the response..
   *
   * @return bulkRecipients
   */
  @Schema(
      description =
          "A complex type containing information about the bulk recipients in the response.")
  public java.util.List<BulkRecipient> getBulkRecipients() {
    return bulkRecipients;
  }

  /** setBulkRecipients. */
  public void setBulkRecipients(java.util.List<BulkRecipient> bulkRecipients) {
    this.bulkRecipients = bulkRecipients;
  }

  /**
   * endPosition.
   *
   * @return BulkRecipientsResponse
   */
  public BulkRecipientsResponse endPosition(String endPosition) {
    this.endPosition = endPosition;
    return this;
  }

  /**
   * The last position in the result set. .
   *
   * @return endPosition
   */
  @Schema(description = "The last position in the result set. ")
  public String getEndPosition() {
    return endPosition;
  }

  /** setEndPosition. */
  public void setEndPosition(String endPosition) {
    this.endPosition = endPosition;
  }

  /**
   * nextUri.
   *
   * @return BulkRecipientsResponse
   */
  public BulkRecipientsResponse nextUri(String nextUri) {
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
   * @return BulkRecipientsResponse
   */
  public BulkRecipientsResponse previousUri(String previousUri) {
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
   * resultSetSize.
   *
   * @return BulkRecipientsResponse
   */
  public BulkRecipientsResponse resultSetSize(String resultSetSize) {
    this.resultSetSize = resultSetSize;
    return this;
  }

  /**
   * The number of results returned in this response. .
   *
   * @return resultSetSize
   */
  @Schema(description = "The number of results returned in this response. ")
  public String getResultSetSize() {
    return resultSetSize;
  }

  /** setResultSetSize. */
  public void setResultSetSize(String resultSetSize) {
    this.resultSetSize = resultSetSize;
  }

  /**
   * startPosition.
   *
   * @return BulkRecipientsResponse
   */
  public BulkRecipientsResponse startPosition(String startPosition) {
    this.startPosition = startPosition;
    return this;
  }

  /**
   * Starting position of the current result set..
   *
   * @return startPosition
   */
  @Schema(description = "Starting position of the current result set.")
  public String getStartPosition() {
    return startPosition;
  }

  /** setStartPosition. */
  public void setStartPosition(String startPosition) {
    this.startPosition = startPosition;
  }

  /**
   * totalSetSize.
   *
   * @return BulkRecipientsResponse
   */
  public BulkRecipientsResponse totalSetSize(String totalSetSize) {
    this.totalSetSize = totalSetSize;
    return this;
  }

  /**
   * The total number of items available in the result set. This will always be greater than or
   * equal to the value of the property returning the results in the in the response..
   *
   * @return totalSetSize
   */
  @Schema(
      description =
          "The total number of items available in the result set. This will always be greater than or equal to the value of the property returning the results in the in the response.")
  public String getTotalSetSize() {
    return totalSetSize;
  }

  /** setTotalSetSize. */
  public void setTotalSetSize(String totalSetSize) {
    this.totalSetSize = totalSetSize;
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
    BulkRecipientsResponse bulkRecipientsResponse = (BulkRecipientsResponse) o;
    return Objects.equals(this.bulkRecipients, bulkRecipientsResponse.bulkRecipients)
        && Objects.equals(this.endPosition, bulkRecipientsResponse.endPosition)
        && Objects.equals(this.nextUri, bulkRecipientsResponse.nextUri)
        && Objects.equals(this.previousUri, bulkRecipientsResponse.previousUri)
        && Objects.equals(this.resultSetSize, bulkRecipientsResponse.resultSetSize)
        && Objects.equals(this.startPosition, bulkRecipientsResponse.startPosition)
        && Objects.equals(this.totalSetSize, bulkRecipientsResponse.totalSetSize);
  }

  /** Returns the HashCode. */
  @Override
  public int hashCode() {
    return Objects.hash(
        bulkRecipients,
        endPosition,
        nextUri,
        previousUri,
        resultSetSize,
        startPosition,
        totalSetSize);
  }

  /** Converts the given object to string. */
  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class BulkRecipientsResponse {\n");

    sb.append("    bulkRecipients: ").append(toIndentedString(bulkRecipients)).append("\n");
    sb.append("    endPosition: ").append(toIndentedString(endPosition)).append("\n");
    sb.append("    nextUri: ").append(toIndentedString(nextUri)).append("\n");
    sb.append("    previousUri: ").append(toIndentedString(previousUri)).append("\n");
    sb.append("    resultSetSize: ").append(toIndentedString(resultSetSize)).append("\n");
    sb.append("    startPosition: ").append(toIndentedString(startPosition)).append("\n");
    sb.append("    totalSetSize: ").append(toIndentedString(totalSetSize)).append("\n");
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
