package com.docusign.esign.model;

import com.docusign.esign.override.swagger.Schema;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;

/** DocumentHtmlDisplayAnchor. */
public class DocumentHtmlDisplayAnchor {
  @JsonProperty("caseSensitive")
  private Boolean caseSensitive = null;

  @JsonProperty("displaySettings")
  private DocumentHtmlDisplaySettings displaySettings = null;

  @JsonProperty("endAnchor")
  private String endAnchor = null;

  @JsonProperty("removeEndAnchor")
  private Boolean removeEndAnchor = null;

  @JsonProperty("removeStartAnchor")
  private Boolean removeStartAnchor = null;

  @JsonProperty("startAnchor")
  private String startAnchor = null;

  /**
   * caseSensitive.
   *
   * @return DocumentHtmlDisplayAnchor
   */
  public DocumentHtmlDisplayAnchor caseSensitive(Boolean caseSensitive) {
    this.caseSensitive = caseSensitive;
    return this;
  }

  /**
   * .
   *
   * @return caseSensitive
   */
  @Schema(description = "")
  public Boolean isCaseSensitive() {
    return caseSensitive;
  }

  /** setCaseSensitive. */
  public void setCaseSensitive(Boolean caseSensitive) {
    this.caseSensitive = caseSensitive;
  }

  /**
   * displaySettings.
   *
   * @return DocumentHtmlDisplayAnchor
   */
  public DocumentHtmlDisplayAnchor displaySettings(DocumentHtmlDisplaySettings displaySettings) {
    this.displaySettings = displaySettings;
    return this;
  }

  /**
   * This object defines how the HTML section inside the `startAnchor` and `endAnchor` displays..
   *
   * @return displaySettings
   */
  @Schema(
      description =
          "This object defines how the HTML section inside the `startAnchor` and `endAnchor` displays.")
  public DocumentHtmlDisplaySettings getDisplaySettings() {
    return displaySettings;
  }

  /** setDisplaySettings. */
  public void setDisplaySettings(DocumentHtmlDisplaySettings displaySettings) {
    this.displaySettings = displaySettings;
  }

  /**
   * endAnchor.
   *
   * @return DocumentHtmlDisplayAnchor
   */
  public DocumentHtmlDisplayAnchor endAnchor(String endAnchor) {
    this.endAnchor = endAnchor;
    return this;
  }

  /**
   * .
   *
   * @return endAnchor
   */
  @Schema(description = "")
  public String getEndAnchor() {
    return endAnchor;
  }

  /** setEndAnchor. */
  public void setEndAnchor(String endAnchor) {
    this.endAnchor = endAnchor;
  }

  /**
   * removeEndAnchor.
   *
   * @return DocumentHtmlDisplayAnchor
   */
  public DocumentHtmlDisplayAnchor removeEndAnchor(Boolean removeEndAnchor) {
    this.removeEndAnchor = removeEndAnchor;
    return this;
  }

  /**
   * .
   *
   * @return removeEndAnchor
   */
  @Schema(description = "")
  public Boolean isRemoveEndAnchor() {
    return removeEndAnchor;
  }

  /** setRemoveEndAnchor. */
  public void setRemoveEndAnchor(Boolean removeEndAnchor) {
    this.removeEndAnchor = removeEndAnchor;
  }

  /**
   * removeStartAnchor.
   *
   * @return DocumentHtmlDisplayAnchor
   */
  public DocumentHtmlDisplayAnchor removeStartAnchor(Boolean removeStartAnchor) {
    this.removeStartAnchor = removeStartAnchor;
    return this;
  }

  /**
   * .
   *
   * @return removeStartAnchor
   */
  @Schema(description = "")
  public Boolean isRemoveStartAnchor() {
    return removeStartAnchor;
  }

  /** setRemoveStartAnchor. */
  public void setRemoveStartAnchor(Boolean removeStartAnchor) {
    this.removeStartAnchor = removeStartAnchor;
  }

  /**
   * startAnchor.
   *
   * @return DocumentHtmlDisplayAnchor
   */
  public DocumentHtmlDisplayAnchor startAnchor(String startAnchor) {
    this.startAnchor = startAnchor;
    return this;
  }

  /**
   * .
   *
   * @return startAnchor
   */
  @Schema(description = "")
  public String getStartAnchor() {
    return startAnchor;
  }

  /** setStartAnchor. */
  public void setStartAnchor(String startAnchor) {
    this.startAnchor = startAnchor;
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
    DocumentHtmlDisplayAnchor documentHtmlDisplayAnchor = (DocumentHtmlDisplayAnchor) o;
    return Objects.equals(this.caseSensitive, documentHtmlDisplayAnchor.caseSensitive)
        && Objects.equals(this.displaySettings, documentHtmlDisplayAnchor.displaySettings)
        && Objects.equals(this.endAnchor, documentHtmlDisplayAnchor.endAnchor)
        && Objects.equals(this.removeEndAnchor, documentHtmlDisplayAnchor.removeEndAnchor)
        && Objects.equals(this.removeStartAnchor, documentHtmlDisplayAnchor.removeStartAnchor)
        && Objects.equals(this.startAnchor, documentHtmlDisplayAnchor.startAnchor);
  }

  /** Returns the HashCode. */
  @Override
  public int hashCode() {
    return Objects.hash(
        caseSensitive, displaySettings, endAnchor, removeEndAnchor, removeStartAnchor, startAnchor);
  }

  /** Converts the given object to string. */
  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class DocumentHtmlDisplayAnchor {\n");

    sb.append("    caseSensitive: ").append(toIndentedString(caseSensitive)).append("\n");
    sb.append("    displaySettings: ").append(toIndentedString(displaySettings)).append("\n");
    sb.append("    endAnchor: ").append(toIndentedString(endAnchor)).append("\n");
    sb.append("    removeEndAnchor: ").append(toIndentedString(removeEndAnchor)).append("\n");
    sb.append("    removeStartAnchor: ").append(toIndentedString(removeStartAnchor)).append("\n");
    sb.append("    startAnchor: ").append(toIndentedString(startAnchor)).append("\n");
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
