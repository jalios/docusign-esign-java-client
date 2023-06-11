package com.docusign.esign.model;

import com.docusign.esign.override.swagger.Schema;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;

/** DocumentHtmlDefinitionOriginals. */
public class DocumentHtmlDefinitionOriginals {
  @JsonProperty("htmlDefinitions")
  private java.util.List<DocumentHtmlDefinitionOriginal> htmlDefinitions = null;

  /**
   * htmlDefinitions.
   *
   * @return DocumentHtmlDefinitionOriginals
   */
  public DocumentHtmlDefinitionOriginals htmlDefinitions(
      java.util.List<DocumentHtmlDefinitionOriginal> htmlDefinitions) {
    this.htmlDefinitions = htmlDefinitions;
    return this;
  }

  /**
   * addHtmlDefinitionsItem.
   *
   * @return DocumentHtmlDefinitionOriginals
   */
  public DocumentHtmlDefinitionOriginals addHtmlDefinitionsItem(
      DocumentHtmlDefinitionOriginal htmlDefinitionsItem) {
    if (this.htmlDefinitions == null) {
      this.htmlDefinitions = new java.util.ArrayList<>();
    }
    this.htmlDefinitions.add(htmlDefinitionsItem);
    return this;
  }

  /**
   * .
   *
   * @return htmlDefinitions
   */
  @Schema(description = "")
  public java.util.List<DocumentHtmlDefinitionOriginal> getHtmlDefinitions() {
    return htmlDefinitions;
  }

  /** setHtmlDefinitions. */
  public void setHtmlDefinitions(java.util.List<DocumentHtmlDefinitionOriginal> htmlDefinitions) {
    this.htmlDefinitions = htmlDefinitions;
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
    DocumentHtmlDefinitionOriginals documentHtmlDefinitionOriginals =
        (DocumentHtmlDefinitionOriginals) o;
    return Objects.equals(this.htmlDefinitions, documentHtmlDefinitionOriginals.htmlDefinitions);
  }

  /** Returns the HashCode. */
  @Override
  public int hashCode() {
    return Objects.hash(htmlDefinitions);
  }

  /** Converts the given object to string. */
  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class DocumentHtmlDefinitionOriginals {\n");

    sb.append("    htmlDefinitions: ").append(toIndentedString(htmlDefinitions)).append("\n");
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
