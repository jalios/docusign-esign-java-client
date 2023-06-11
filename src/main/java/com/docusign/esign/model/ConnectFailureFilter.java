package com.docusign.esign.model;

import com.docusign.esign.override.swagger.Schema;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;

/** A list of failed envelope IDs to retry.. */
@Schema(description = "A list of failed envelope IDs to retry.")
public class ConnectFailureFilter {
  @JsonProperty("envelopeIds")
  private java.util.List<String> envelopeIds = null;

  @JsonProperty("synchronous")
  private String synchronous = null;

  /**
   * envelopeIds.
   *
   * @return ConnectFailureFilter
   */
  public ConnectFailureFilter envelopeIds(java.util.List<String> envelopeIds) {
    this.envelopeIds = envelopeIds;
    return this;
  }

  /**
   * addEnvelopeIdsItem.
   *
   * @return ConnectFailureFilter
   */
  public ConnectFailureFilter addEnvelopeIdsItem(String envelopeIdsItem) {
    if (this.envelopeIds == null) {
      this.envelopeIds = new java.util.ArrayList<>();
    }
    this.envelopeIds.add(envelopeIdsItem);
    return this;
  }

  /**
   * .
   *
   * @return envelopeIds
   */
  @Schema(description = "")
  public java.util.List<String> getEnvelopeIds() {
    return envelopeIds;
  }

  /** setEnvelopeIds. */
  public void setEnvelopeIds(java.util.List<String> envelopeIds) {
    this.envelopeIds = envelopeIds;
  }

  /**
   * synchronous.
   *
   * @return ConnectFailureFilter
   */
  public ConnectFailureFilter synchronous(String synchronous) {
    this.synchronous = synchronous;
    return this;
  }

  /**
   * .
   *
   * @return synchronous
   */
  @Schema(description = "")
  public String getSynchronous() {
    return synchronous;
  }

  /** setSynchronous. */
  public void setSynchronous(String synchronous) {
    this.synchronous = synchronous;
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
    ConnectFailureFilter connectFailureFilter = (ConnectFailureFilter) o;
    return Objects.equals(this.envelopeIds, connectFailureFilter.envelopeIds)
        && Objects.equals(this.synchronous, connectFailureFilter.synchronous);
  }

  /** Returns the HashCode. */
  @Override
  public int hashCode() {
    return Objects.hash(envelopeIds, synchronous);
  }

  /** Converts the given object to string. */
  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class ConnectFailureFilter {\n");

    sb.append("    envelopeIds: ").append(toIndentedString(envelopeIds)).append("\n");
    sb.append("    synchronous: ").append(toIndentedString(synchronous)).append("\n");
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
