package com.docusign.esign.model;

import com.docusign.esign.override.swagger.Schema;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;

/** PaymentProcessorInformation. */
public class PaymentProcessorInformation {
  @JsonProperty("address")
  private AddressInformation address = null;

  @JsonProperty("billingAgreementId")
  private String billingAgreementId = null;

  @JsonProperty("email")
  private String email = null;

  /**
   * address.
   *
   * @return PaymentProcessorInformation
   */
  public PaymentProcessorInformation address(AddressInformation address) {
    this.address = address;
    return this;
  }

  /**
   * The mailing address associated with the payment processor..
   *
   * @return address
   */
  @Schema(description = "The mailing address associated with the payment processor.")
  public AddressInformation getAddress() {
    return address;
  }

  /** setAddress. */
  public void setAddress(AddressInformation address) {
    this.address = address;
  }

  /**
   * billingAgreementId.
   *
   * @return PaymentProcessorInformation
   */
  public PaymentProcessorInformation billingAgreementId(String billingAgreementId) {
    this.billingAgreementId = billingAgreementId;
    return this;
  }

  /**
   * .
   *
   * @return billingAgreementId
   */
  @Schema(description = "")
  public String getBillingAgreementId() {
    return billingAgreementId;
  }

  /** setBillingAgreementId. */
  public void setBillingAgreementId(String billingAgreementId) {
    this.billingAgreementId = billingAgreementId;
  }

  /**
   * email.
   *
   * @return PaymentProcessorInformation
   */
  public PaymentProcessorInformation email(String email) {
    this.email = email;
    return this;
  }

  /**
   * .
   *
   * @return email
   */
  @Schema(description = "")
  public String getEmail() {
    return email;
  }

  /** setEmail. */
  public void setEmail(String email) {
    this.email = email;
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
    PaymentProcessorInformation paymentProcessorInformation = (PaymentProcessorInformation) o;
    return Objects.equals(this.address, paymentProcessorInformation.address)
        && Objects.equals(this.billingAgreementId, paymentProcessorInformation.billingAgreementId)
        && Objects.equals(this.email, paymentProcessorInformation.email);
  }

  /** Returns the HashCode. */
  @Override
  public int hashCode() {
    return Objects.hash(address, billingAgreementId, email);
  }

  /** Converts the given object to string. */
  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class PaymentProcessorInformation {\n");

    sb.append("    address: ").append(toIndentedString(address)).append("\n");
    sb.append("    billingAgreementId: ").append(toIndentedString(billingAgreementId)).append("\n");
    sb.append("    email: ").append(toIndentedString(email)).append("\n");
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
