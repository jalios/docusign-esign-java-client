package com.docusign.esign.model;

import com.docusign.esign.override.swagger.Schema;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;

/** PaymentSignerValues. */
public class PaymentSignerValues {
  @JsonProperty("paymentOption")
  private String paymentOption = null;

  /**
   * paymentOption.
   *
   * @return PaymentSignerValues
   */
  public PaymentSignerValues paymentOption(String paymentOption) {
    this.paymentOption = paymentOption;
    return this;
  }

  /**
   * .
   *
   * @return paymentOption
   */
  @Schema(description = "")
  public String getPaymentOption() {
    return paymentOption;
  }

  /** setPaymentOption. */
  public void setPaymentOption(String paymentOption) {
    this.paymentOption = paymentOption;
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
    PaymentSignerValues paymentSignerValues = (PaymentSignerValues) o;
    return Objects.equals(this.paymentOption, paymentSignerValues.paymentOption);
  }

  /** Returns the HashCode. */
  @Override
  public int hashCode() {
    return Objects.hash(paymentOption);
  }

  /** Converts the given object to string. */
  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class PaymentSignerValues {\n");

    sb.append("    paymentOption: ").append(toIndentedString(paymentOption)).append("\n");
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
