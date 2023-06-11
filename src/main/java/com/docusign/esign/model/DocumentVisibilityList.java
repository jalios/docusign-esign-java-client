package com.docusign.esign.model;

import com.docusign.esign.override.swagger.Schema;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;

/**
 * A list of &#x60;documentVisibility&#x60; objects that specify whether documents are visible to
 * recipients..
 */
@Schema(
    description =
        "A list of `documentVisibility` objects that specify whether documents are visible to recipients.")
public class DocumentVisibilityList {
  @JsonProperty("documentVisibility")
  private java.util.List<DocumentVisibility> documentVisibility = null;

  /**
   * documentVisibility.
   *
   * @return DocumentVisibilityList
   */
  public DocumentVisibilityList documentVisibility(
      java.util.List<DocumentVisibility> documentVisibility) {
    this.documentVisibility = documentVisibility;
    return this;
  }

  /**
   * addDocumentVisibilityItem.
   *
   * @return DocumentVisibilityList
   */
  public DocumentVisibilityList addDocumentVisibilityItem(
      DocumentVisibility documentVisibilityItem) {
    if (this.documentVisibility == null) {
      this.documentVisibility = new java.util.ArrayList<>();
    }
    this.documentVisibility.add(documentVisibilityItem);
    return this;
  }

  /**
   * .
   *
   * @return documentVisibility
   */
  @Schema(description = "")
  public java.util.List<DocumentVisibility> getDocumentVisibility() {
    return documentVisibility;
  }

  /** setDocumentVisibility. */
  public void setDocumentVisibility(java.util.List<DocumentVisibility> documentVisibility) {
    this.documentVisibility = documentVisibility;
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
    DocumentVisibilityList documentVisibilityList = (DocumentVisibilityList) o;
    return Objects.equals(this.documentVisibility, documentVisibilityList.documentVisibility);
  }

  /** Returns the HashCode. */
  @Override
  public int hashCode() {
    return Objects.hash(documentVisibility);
  }

  /** Converts the given object to string. */
  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class DocumentVisibilityList {\n");

    sb.append("    documentVisibility: ").append(toIndentedString(documentVisibility)).append("\n");
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
