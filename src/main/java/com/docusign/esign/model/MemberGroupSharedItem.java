package com.docusign.esign.model;

import com.docusign.esign.override.swagger.Schema;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;

/** Information about items shared among groups.. */
@Schema(description = "Information about items shared among groups.")
public class MemberGroupSharedItem {
  @JsonProperty("errorDetails")
  private ErrorDetails errorDetails = null;

  @JsonProperty("group")
  private Group group = null;

  @JsonProperty("shared")
  private String shared = null;

  /**
   * errorDetails.
   *
   * @return MemberGroupSharedItem
   */
  public MemberGroupSharedItem errorDetails(ErrorDetails errorDetails) {
    this.errorDetails = errorDetails;
    return this;
  }

  /**
   * Array or errors..
   *
   * @return errorDetails
   */
  @Schema(description = "Array or errors.")
  public ErrorDetails getErrorDetails() {
    return errorDetails;
  }

  /** setErrorDetails. */
  public void setErrorDetails(ErrorDetails errorDetails) {
    this.errorDetails = errorDetails;
  }

  /**
   * group.
   *
   * @return MemberGroupSharedItem
   */
  public MemberGroupSharedItem group(Group group) {
    this.group = group;
    return this;
  }

  /**
   * The group sharing the item..
   *
   * @return group
   */
  @Schema(description = "The group sharing the item.")
  public Group getGroup() {
    return group;
  }

  /** setGroup. */
  public void setGroup(Group group) {
    this.group = group;
  }

  /**
   * shared.
   *
   * @return MemberGroupSharedItem
   */
  public MemberGroupSharedItem shared(String shared) {
    this.shared = shared;
    return this;
  }

  /**
   * When set to **true**, this custom tab is shared..
   *
   * @return shared
   */
  @Schema(description = "When set to **true**, this custom tab is shared.")
  public String getShared() {
    return shared;
  }

  /** setShared. */
  public void setShared(String shared) {
    this.shared = shared;
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
    MemberGroupSharedItem memberGroupSharedItem = (MemberGroupSharedItem) o;
    return Objects.equals(this.errorDetails, memberGroupSharedItem.errorDetails)
        && Objects.equals(this.group, memberGroupSharedItem.group)
        && Objects.equals(this.shared, memberGroupSharedItem.shared);
  }

  /** Returns the HashCode. */
  @Override
  public int hashCode() {
    return Objects.hash(errorDetails, group, shared);
  }

  /** Converts the given object to string. */
  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class MemberGroupSharedItem {\n");

    sb.append("    errorDetails: ").append(toIndentedString(errorDetails)).append("\n");
    sb.append("    group: ").append(toIndentedString(group)).append("\n");
    sb.append("    shared: ").append(toIndentedString(shared)).append("\n");
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
