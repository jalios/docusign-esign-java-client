package com.docusign.esign.model;

import com.docusign.esign.override.swagger.Schema;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;

/** BulkProcessingLists. */
public class BulkProcessingLists {
  @JsonProperty("bulkProcessListIds")
  private java.util.List<String> bulkProcessListIds = null;

  /**
   * bulkProcessListIds.
   *
   * @return BulkProcessingLists
   */
  public BulkProcessingLists bulkProcessListIds(java.util.List<String> bulkProcessListIds) {
    this.bulkProcessListIds = bulkProcessListIds;
    return this;
  }

  /**
   * addBulkProcessListIdsItem.
   *
   * @return BulkProcessingLists
   */
  public BulkProcessingLists addBulkProcessListIdsItem(String bulkProcessListIdsItem) {
    if (this.bulkProcessListIds == null) {
      this.bulkProcessListIds = new java.util.ArrayList<>();
    }
    this.bulkProcessListIds.add(bulkProcessListIdsItem);
    return this;
  }

  /**
   * .
   *
   * @return bulkProcessListIds
   */
  @Schema(description = "")
  public java.util.List<String> getBulkProcessListIds() {
    return bulkProcessListIds;
  }

  /** setBulkProcessListIds. */
  public void setBulkProcessListIds(java.util.List<String> bulkProcessListIds) {
    this.bulkProcessListIds = bulkProcessListIds;
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
    BulkProcessingLists bulkProcessingLists = (BulkProcessingLists) o;
    return Objects.equals(this.bulkProcessListIds, bulkProcessingLists.bulkProcessListIds);
  }

  /** Returns the HashCode. */
  @Override
  public int hashCode() {
    return Objects.hash(bulkProcessListIds);
  }

  /** Converts the given object to string. */
  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class BulkProcessingLists {\n");

    sb.append("    bulkProcessListIds: ").append(toIndentedString(bulkProcessListIds)).append("\n");
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
