package com.docusign.esign.model;

import com.docusign.esign.override.swagger.Schema;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;

/** A paged list of jurisdictions.. */
@Schema(description = "A paged list of jurisdictions.")
public class NotaryJurisdictionList {
  @JsonProperty("endPosition")
  private String endPosition = null;

  @JsonProperty("nextUri")
  private String nextUri = null;

  @JsonProperty("notaryJurisdictions")
  private java.util.List<NotaryJurisdiction> notaryJurisdictions = null;

  @JsonProperty("previousUri")
  private String previousUri = null;

  @JsonProperty("resultSetSize")
  private String resultSetSize = null;

  @JsonProperty("startPosition")
  private String startPosition = null;

  @JsonProperty("totalSetSize")
  private String totalSetSize = null;

  /**
   * endPosition.
   *
   * @return NotaryJurisdictionList
   */
  public NotaryJurisdictionList endPosition(String endPosition) {
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
   * @return NotaryJurisdictionList
   */
  public NotaryJurisdictionList nextUri(String nextUri) {
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
   * notaryJurisdictions.
   *
   * @return NotaryJurisdictionList
   */
  public NotaryJurisdictionList notaryJurisdictions(
      java.util.List<NotaryJurisdiction> notaryJurisdictions) {
    this.notaryJurisdictions = notaryJurisdictions;
    return this;
  }

  /**
   * addNotaryJurisdictionsItem.
   *
   * @return NotaryJurisdictionList
   */
  public NotaryJurisdictionList addNotaryJurisdictionsItem(
      NotaryJurisdiction notaryJurisdictionsItem) {
    if (this.notaryJurisdictions == null) {
      this.notaryJurisdictions = new java.util.ArrayList<>();
    }
    this.notaryJurisdictions.add(notaryJurisdictionsItem);
    return this;
  }

  /**
   * .
   *
   * @return notaryJurisdictions
   */
  @Schema(description = "")
  public java.util.List<NotaryJurisdiction> getNotaryJurisdictions() {
    return notaryJurisdictions;
  }

  /** setNotaryJurisdictions. */
  public void setNotaryJurisdictions(java.util.List<NotaryJurisdiction> notaryJurisdictions) {
    this.notaryJurisdictions = notaryJurisdictions;
  }

  /**
   * previousUri.
   *
   * @return NotaryJurisdictionList
   */
  public NotaryJurisdictionList previousUri(String previousUri) {
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
   * @return NotaryJurisdictionList
   */
  public NotaryJurisdictionList resultSetSize(String resultSetSize) {
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
   * @return NotaryJurisdictionList
   */
  public NotaryJurisdictionList startPosition(String startPosition) {
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
   * @return NotaryJurisdictionList
   */
  public NotaryJurisdictionList totalSetSize(String totalSetSize) {
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
    NotaryJurisdictionList notaryJurisdictionList = (NotaryJurisdictionList) o;
    return Objects.equals(this.endPosition, notaryJurisdictionList.endPosition)
        && Objects.equals(this.nextUri, notaryJurisdictionList.nextUri)
        && Objects.equals(this.notaryJurisdictions, notaryJurisdictionList.notaryJurisdictions)
        && Objects.equals(this.previousUri, notaryJurisdictionList.previousUri)
        && Objects.equals(this.resultSetSize, notaryJurisdictionList.resultSetSize)
        && Objects.equals(this.startPosition, notaryJurisdictionList.startPosition)
        && Objects.equals(this.totalSetSize, notaryJurisdictionList.totalSetSize);
  }

  /** Returns the HashCode. */
  @Override
  public int hashCode() {
    return Objects.hash(
        endPosition,
        nextUri,
        notaryJurisdictions,
        previousUri,
        resultSetSize,
        startPosition,
        totalSetSize);
  }

  /** Converts the given object to string. */
  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class NotaryJurisdictionList {\n");

    sb.append("    endPosition: ").append(toIndentedString(endPosition)).append("\n");
    sb.append("    nextUri: ").append(toIndentedString(nextUri)).append("\n");
    sb.append("    notaryJurisdictions: ")
        .append(toIndentedString(notaryJurisdictions))
        .append("\n");
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
