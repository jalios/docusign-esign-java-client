package com.docusign.esign.model;

import com.docusign.esign.override.swagger.Schema;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;

/** Ssn4InformationInput. */
public class Ssn4InformationInput {
  @JsonProperty("displayLevelCode")
  private String displayLevelCode = null;

  @JsonProperty("receiveInResponse")
  private String receiveInResponse = null;

  @JsonProperty("ssn4")
  private String ssn4 = null;

  /**
   * displayLevelCode.
   *
   * @return Ssn4InformationInput
   */
  public Ssn4InformationInput displayLevelCode(String displayLevelCode) {
    this.displayLevelCode = displayLevelCode;
    return this;
  }

  /**
   * Specifies the display level for the recipient. Valid values are: * ReadOnly * Editable *
   * DoNotDisplay.
   *
   * @return displayLevelCode
   */
  @Schema(
      description =
          "Specifies the display level for the recipient.  Valid values are:   * ReadOnly * Editable * DoNotDisplay")
  public String getDisplayLevelCode() {
    return displayLevelCode;
  }

  /** setDisplayLevelCode. */
  public void setDisplayLevelCode(String displayLevelCode) {
    this.displayLevelCode = displayLevelCode;
  }

  /**
   * receiveInResponse.
   *
   * @return Ssn4InformationInput
   */
  public Ssn4InformationInput receiveInResponse(String receiveInResponse) {
    this.receiveInResponse = receiveInResponse;
    return this;
  }

  /**
   * When set to **true**, the information needs to be returned in the response..
   *
   * @return receiveInResponse
   */
  @Schema(
      description = "When set to **true**, the information needs to be returned in the response.")
  public String getReceiveInResponse() {
    return receiveInResponse;
  }

  /** setReceiveInResponse. */
  public void setReceiveInResponse(String receiveInResponse) {
    this.receiveInResponse = receiveInResponse;
  }

  /**
   * ssn4.
   *
   * @return Ssn4InformationInput
   */
  public Ssn4InformationInput ssn4(String ssn4) {
    this.ssn4 = ssn4;
    return this;
  }

  /**
   * The last four digits of the recipient's Social Security Number (SSN)..
   *
   * @return ssn4
   */
  @Schema(description = "The last four digits of the recipient's Social Security Number (SSN).")
  public String getSsn4() {
    return ssn4;
  }

  /** setSsn4. */
  public void setSsn4(String ssn4) {
    this.ssn4 = ssn4;
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
    Ssn4InformationInput ssn4InformationInput = (Ssn4InformationInput) o;
    return Objects.equals(this.displayLevelCode, ssn4InformationInput.displayLevelCode)
        && Objects.equals(this.receiveInResponse, ssn4InformationInput.receiveInResponse)
        && Objects.equals(this.ssn4, ssn4InformationInput.ssn4);
  }

  /** Returns the HashCode. */
  @Override
  public int hashCode() {
    return Objects.hash(displayLevelCode, receiveInResponse, ssn4);
  }

  /** Converts the given object to string. */
  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class Ssn4InformationInput {\n");

    sb.append("    displayLevelCode: ").append(toIndentedString(displayLevelCode)).append("\n");
    sb.append("    receiveInResponse: ").append(toIndentedString(receiveInResponse)).append("\n");
    sb.append("    ssn4: ").append(toIndentedString(ssn4)).append("\n");
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
