package com.docusign.esign.model;

import com.docusign.esign.override.swagger.Schema;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;

/**
 * Specifies the area in which a date stamp is placed. This parameter uses pixel positioning to draw
 * a rectangle at the center of the stamp area. The stamp is superimposed on top of this central
 * area. This property contains the following information about the central rectangle: -
 * &#x60;DateAreaX&#x60;: The X axis position of the top-left corner. - &#x60;DateAreaY&#x60;: The Y
 * axis position of the top-left corner. - &#x60;DateAreaWidth&#x60;: The width of the rectangle. -
 * &#x60;DateAreaHeight&#x60;: The height of the rectangle..
 */
@Schema(
    description =
        "Specifies the area in which a date stamp is placed. This parameter uses pixel positioning to draw a rectangle at the center of the stamp area. The stamp is superimposed on top of this central area.  This property contains the following information about the central rectangle:  - `DateAreaX`: The X axis position of the top-left corner. - `DateAreaY`: The Y axis position of the top-left corner. - `DateAreaWidth`: The width of the rectangle. - `DateAreaHeight`: The height of the rectangle.")
public class DateStampProperties {
  @JsonProperty("dateAreaHeight")
  private String dateAreaHeight = null;

  @JsonProperty("dateAreaWidth")
  private String dateAreaWidth = null;

  @JsonProperty("dateAreaX")
  private String dateAreaX = null;

  @JsonProperty("dateAreaY")
  private String dateAreaY = null;

  /**
   * dateAreaHeight.
   *
   * @return DateStampProperties
   */
  public DateStampProperties dateAreaHeight(String dateAreaHeight) {
    this.dateAreaHeight = dateAreaHeight;
    return this;
  }

  /**
   * .
   *
   * @return dateAreaHeight
   */
  @Schema(description = "")
  public String getDateAreaHeight() {
    return dateAreaHeight;
  }

  /** setDateAreaHeight. */
  public void setDateAreaHeight(String dateAreaHeight) {
    this.dateAreaHeight = dateAreaHeight;
  }

  /**
   * dateAreaWidth.
   *
   * @return DateStampProperties
   */
  public DateStampProperties dateAreaWidth(String dateAreaWidth) {
    this.dateAreaWidth = dateAreaWidth;
    return this;
  }

  /**
   * .
   *
   * @return dateAreaWidth
   */
  @Schema(description = "")
  public String getDateAreaWidth() {
    return dateAreaWidth;
  }

  /** setDateAreaWidth. */
  public void setDateAreaWidth(String dateAreaWidth) {
    this.dateAreaWidth = dateAreaWidth;
  }

  /**
   * dateAreaX.
   *
   * @return DateStampProperties
   */
  public DateStampProperties dateAreaX(String dateAreaX) {
    this.dateAreaX = dateAreaX;
    return this;
  }

  /**
   * .
   *
   * @return dateAreaX
   */
  @Schema(description = "")
  public String getDateAreaX() {
    return dateAreaX;
  }

  /** setDateAreaX. */
  public void setDateAreaX(String dateAreaX) {
    this.dateAreaX = dateAreaX;
  }

  /**
   * dateAreaY.
   *
   * @return DateStampProperties
   */
  public DateStampProperties dateAreaY(String dateAreaY) {
    this.dateAreaY = dateAreaY;
    return this;
  }

  /**
   * .
   *
   * @return dateAreaY
   */
  @Schema(description = "")
  public String getDateAreaY() {
    return dateAreaY;
  }

  /** setDateAreaY. */
  public void setDateAreaY(String dateAreaY) {
    this.dateAreaY = dateAreaY;
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
    DateStampProperties dateStampProperties = (DateStampProperties) o;
    return Objects.equals(this.dateAreaHeight, dateStampProperties.dateAreaHeight)
        && Objects.equals(this.dateAreaWidth, dateStampProperties.dateAreaWidth)
        && Objects.equals(this.dateAreaX, dateStampProperties.dateAreaX)
        && Objects.equals(this.dateAreaY, dateStampProperties.dateAreaY);
  }

  /** Returns the HashCode. */
  @Override
  public int hashCode() {
    return Objects.hash(dateAreaHeight, dateAreaWidth, dateAreaX, dateAreaY);
  }

  /** Converts the given object to string. */
  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class DateStampProperties {\n");

    sb.append("    dateAreaHeight: ").append(toIndentedString(dateAreaHeight)).append("\n");
    sb.append("    dateAreaWidth: ").append(toIndentedString(dateAreaWidth)).append("\n");
    sb.append("    dateAreaX: ").append(toIndentedString(dateAreaX)).append("\n");
    sb.append("    dateAreaY: ").append(toIndentedString(dateAreaY)).append("\n");
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
