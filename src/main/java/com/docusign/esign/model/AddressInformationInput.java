package com.docusign.esign.model;

import com.docusign.esign.override.swagger.Schema;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;

/** Contains address input information.. */
@Schema(description = "Contains address input information.")
public class AddressInformationInput {
  @JsonProperty("addressInformation")
  private AddressInformation addressInformation = null;

  @JsonProperty("displayLevelCode")
  private String displayLevelCode = null;

  @JsonProperty("receiveInResponse")
  private String receiveInResponse = null;

  /**
   * addressInformation.
   *
   * @return AddressInformationInput
   */
  public AddressInformationInput addressInformation(AddressInformation addressInformation) {
    this.addressInformation = addressInformation;
    return this;
  }

  /**
   * A complex type that contains the following information for the new account: `address1`,
   * `address2`, `city`, `country`, `fax`, `phone`, `postalCode` and `stateOrProvince`. The maximum
   * characters for the strings are: * `address1`, `address2`, `city`, `country` and
   * `stateOrProvince`: 100 characters * `postalCode`, `phone`, and `fax`: 20 characters **Note:**
   * If country is US (United States), `stateOrProvince` codes are validated. Otherwise,
   * `stateOrProvince` is treated as a non-validated string used to specify a state, province, or
   * region..
   *
   * @return addressInformation
   */
  @Schema(
      description =
          "A complex type that contains the following information for the new account: `address1`, `address2`, `city`, `country`, `fax`, `phone`, `postalCode` and `stateOrProvince`.  The maximum characters for the strings are: * `address1`, `address2`, `city`, `country` and `stateOrProvince`: 100 characters * `postalCode`, `phone`, and `fax`: 20 characters  **Note:** If country is US (United States), `stateOrProvince` codes are validated. Otherwise, `stateOrProvince` is treated as a non-validated string used to specify a state, province, or region.")
  public AddressInformation getAddressInformation() {
    return addressInformation;
  }

  /** setAddressInformation. */
  public void setAddressInformation(AddressInformation addressInformation) {
    this.addressInformation = addressInformation;
  }

  /**
   * displayLevelCode.
   *
   * @return AddressInformationInput
   */
  public AddressInformationInput displayLevelCode(String displayLevelCode) {
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
   * @return AddressInformationInput
   */
  public AddressInformationInput receiveInResponse(String receiveInResponse) {
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
    AddressInformationInput addressInformationInput = (AddressInformationInput) o;
    return Objects.equals(this.addressInformation, addressInformationInput.addressInformation)
        && Objects.equals(this.displayLevelCode, addressInformationInput.displayLevelCode)
        && Objects.equals(this.receiveInResponse, addressInformationInput.receiveInResponse);
  }

  /** Returns the HashCode. */
  @Override
  public int hashCode() {
    return Objects.hash(addressInformation, displayLevelCode, receiveInResponse);
  }

  /** Converts the given object to string. */
  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class AddressInformationInput {\n");

    sb.append("    addressInformation: ").append(toIndentedString(addressInformation)).append("\n");
    sb.append("    displayLevelCode: ").append(toIndentedString(displayLevelCode)).append("\n");
    sb.append("    receiveInResponse: ").append(toIndentedString(receiveInResponse)).append("\n");
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
