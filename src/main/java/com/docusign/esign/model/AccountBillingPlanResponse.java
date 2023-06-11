package com.docusign.esign.model;

import com.docusign.esign.override.swagger.Schema;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;

/** Defines an account billing plan response object.. */
@Schema(description = "Defines an account billing plan response object.")
public class AccountBillingPlanResponse {
  @JsonProperty("billingAddress")
  private AccountAddress billingAddress = null;

  @JsonProperty("billingAddressIsCreditCardAddress")
  private String billingAddressIsCreditCardAddress = null;

  @JsonProperty("billingPlan")
  private AccountBillingPlan billingPlan = null;

  @JsonProperty("creditCardInformation")
  private CreditCardInformation creditCardInformation = null;

  @JsonProperty("directDebitProcessorInformation")
  private DirectDebitProcessorInformation directDebitProcessorInformation = null;

  @JsonProperty("downgradePlanInformation")
  private DowngradePlanUpdateResponse downgradePlanInformation = null;

  @JsonProperty("downgradeRequestInformation")
  private DowngradeRequestInformation downgradeRequestInformation = null;

  @JsonProperty("entityInformation")
  private BillingEntityInformationResponse entityInformation = null;

  @JsonProperty("paymentMethod")
  private String paymentMethod = null;

  @JsonProperty("paymentProcessorInformation")
  private PaymentProcessorInformation paymentProcessorInformation = null;

  @JsonProperty("referralInformation")
  private ReferralInformation referralInformation = null;

  @JsonProperty("successorPlans")
  private java.util.List<BillingPlan> successorPlans = null;

  @JsonProperty("taxExemptId")
  private String taxExemptId = null;

  /**
   * billingAddress.
   *
   * @return AccountBillingPlanResponse
   */
  public AccountBillingPlanResponse billingAddress(AccountAddress billingAddress) {
    this.billingAddress = billingAddress;
    return this;
  }

  /**
   * The billing address for the account..
   *
   * @return billingAddress
   */
  @Schema(description = "The billing address for the account.")
  public AccountAddress getBillingAddress() {
    return billingAddress;
  }

  /** setBillingAddress. */
  public void setBillingAddress(AccountAddress billingAddress) {
    this.billingAddress = billingAddress;
  }

  /**
   * billingAddressIsCreditCardAddress.
   *
   * @return AccountBillingPlanResponse
   */
  public AccountBillingPlanResponse billingAddressIsCreditCardAddress(
      String billingAddressIsCreditCardAddress) {
    this.billingAddressIsCreditCardAddress = billingAddressIsCreditCardAddress;
    return this;
  }

  /**
   * When set to **true**, the credit card address information is the same as that returned as the
   * billing address. If false, then the billing address is considered a billing contact address,
   * and the credit card address can be different..
   *
   * @return billingAddressIsCreditCardAddress
   */
  @Schema(
      description =
          "When set to **true**, the credit card address information is the same as that returned as the billing address. If false, then the billing address is considered a billing contact address, and the credit card address can be different.")
  public String getBillingAddressIsCreditCardAddress() {
    return billingAddressIsCreditCardAddress;
  }

  /** setBillingAddressIsCreditCardAddress. */
  public void setBillingAddressIsCreditCardAddress(String billingAddressIsCreditCardAddress) {
    this.billingAddressIsCreditCardAddress = billingAddressIsCreditCardAddress;
  }

  /**
   * billingPlan.
   *
   * @return AccountBillingPlanResponse
   */
  public AccountBillingPlanResponse billingPlan(AccountBillingPlan billingPlan) {
    this.billingPlan = billingPlan;
    return this;
  }

  /**
   * An object that contains details about the billing plan..
   *
   * @return billingPlan
   */
  @Schema(description = "An object that contains details about the billing plan.")
  public AccountBillingPlan getBillingPlan() {
    return billingPlan;
  }

  /** setBillingPlan. */
  public void setBillingPlan(AccountBillingPlan billingPlan) {
    this.billingPlan = billingPlan;
  }

  /**
   * creditCardInformation.
   *
   * @return AccountBillingPlanResponse
   */
  public AccountBillingPlanResponse creditCardInformation(
      CreditCardInformation creditCardInformation) {
    this.creditCardInformation = creditCardInformation;
    return this;
  }

  /**
   * A complex type that has information about the credit card used to pay for this account..
   *
   * @return creditCardInformation
   */
  @Schema(
      description =
          "A complex type that has information about the credit card used to pay for this account.")
  public CreditCardInformation getCreditCardInformation() {
    return creditCardInformation;
  }

  /** setCreditCardInformation. */
  public void setCreditCardInformation(CreditCardInformation creditCardInformation) {
    this.creditCardInformation = creditCardInformation;
  }

  /**
   * directDebitProcessorInformation.
   *
   * @return AccountBillingPlanResponse
   */
  public AccountBillingPlanResponse directDebitProcessorInformation(
      DirectDebitProcessorInformation directDebitProcessorInformation) {
    this.directDebitProcessorInformation = directDebitProcessorInformation;
    return this;
  }

  /**
   * Information about the bank that processes direct debits for the payment plan..
   *
   * @return directDebitProcessorInformation
   */
  @Schema(
      description = "Information about the bank that processes direct debits for the payment plan.")
  public DirectDebitProcessorInformation getDirectDebitProcessorInformation() {
    return directDebitProcessorInformation;
  }

  /** setDirectDebitProcessorInformation. */
  public void setDirectDebitProcessorInformation(
      DirectDebitProcessorInformation directDebitProcessorInformation) {
    this.directDebitProcessorInformation = directDebitProcessorInformation;
  }

  /**
   * downgradePlanInformation.
   *
   * @return AccountBillingPlanResponse
   */
  public AccountBillingPlanResponse downgradePlanInformation(
      DowngradePlanUpdateResponse downgradePlanInformation) {
    this.downgradePlanInformation = downgradePlanInformation;
    return this;
  }

  /**
   * .
   *
   * @return downgradePlanInformation
   */
  @Schema(description = "")
  public DowngradePlanUpdateResponse getDowngradePlanInformation() {
    return downgradePlanInformation;
  }

  /** setDowngradePlanInformation. */
  public void setDowngradePlanInformation(DowngradePlanUpdateResponse downgradePlanInformation) {
    this.downgradePlanInformation = downgradePlanInformation;
  }

  /**
   * downgradeRequestInformation.
   *
   * @return AccountBillingPlanResponse
   */
  public AccountBillingPlanResponse downgradeRequestInformation(
      DowngradeRequestInformation downgradeRequestInformation) {
    this.downgradeRequestInformation = downgradeRequestInformation;
    return this;
  }

  /**
   * .
   *
   * @return downgradeRequestInformation
   */
  @Schema(description = "")
  public DowngradeRequestInformation getDowngradeRequestInformation() {
    return downgradeRequestInformation;
  }

  /** setDowngradeRequestInformation. */
  public void setDowngradeRequestInformation(
      DowngradeRequestInformation downgradeRequestInformation) {
    this.downgradeRequestInformation = downgradeRequestInformation;
  }

  /**
   * entityInformation.
   *
   * @return AccountBillingPlanResponse
   */
  public AccountBillingPlanResponse entityInformation(
      BillingEntityInformationResponse entityInformation) {
    this.entityInformation = entityInformation;
    return this;
  }

  /**
   * .
   *
   * @return entityInformation
   */
  @Schema(description = "")
  public BillingEntityInformationResponse getEntityInformation() {
    return entityInformation;
  }

  /** setEntityInformation. */
  public void setEntityInformation(BillingEntityInformationResponse entityInformation) {
    this.entityInformation = entityInformation;
  }

  /**
   * paymentMethod.
   *
   * @return AccountBillingPlanResponse
   */
  public AccountBillingPlanResponse paymentMethod(String paymentMethod) {
    this.paymentMethod = paymentMethod;
    return this;
  }

  /**
   * .
   *
   * @return paymentMethod
   */
  @Schema(description = "")
  public String getPaymentMethod() {
    return paymentMethod;
  }

  /** setPaymentMethod. */
  public void setPaymentMethod(String paymentMethod) {
    this.paymentMethod = paymentMethod;
  }

  /**
   * paymentProcessorInformation.
   *
   * @return AccountBillingPlanResponse
   */
  public AccountBillingPlanResponse paymentProcessorInformation(
      PaymentProcessorInformation paymentProcessorInformation) {
    this.paymentProcessorInformation = paymentProcessorInformation;
    return this;
  }

  /**
   * Information about the entity that processes payments for the billing plan..
   *
   * @return paymentProcessorInformation
   */
  @Schema(
      description = "Information about the entity that processes payments for the billing plan.")
  public PaymentProcessorInformation getPaymentProcessorInformation() {
    return paymentProcessorInformation;
  }

  /** setPaymentProcessorInformation. */
  public void setPaymentProcessorInformation(
      PaymentProcessorInformation paymentProcessorInformation) {
    this.paymentProcessorInformation = paymentProcessorInformation;
  }

  /**
   * referralInformation.
   *
   * @return AccountBillingPlanResponse
   */
  public AccountBillingPlanResponse referralInformation(ReferralInformation referralInformation) {
    this.referralInformation = referralInformation;
    return this;
  }

  /**
   * A complex type that contains properties for entering referral and discount information..
   *
   * @return referralInformation
   */
  @Schema(
      description =
          "A complex type that contains properties for entering referral and discount information.")
  public ReferralInformation getReferralInformation() {
    return referralInformation;
  }

  /** setReferralInformation. */
  public void setReferralInformation(ReferralInformation referralInformation) {
    this.referralInformation = referralInformation;
  }

  /**
   * successorPlans.
   *
   * @return AccountBillingPlanResponse
   */
  public AccountBillingPlanResponse successorPlans(java.util.List<BillingPlan> successorPlans) {
    this.successorPlans = successorPlans;
    return this;
  }

  /**
   * addSuccessorPlansItem.
   *
   * @return AccountBillingPlanResponse
   */
  public AccountBillingPlanResponse addSuccessorPlansItem(BillingPlan successorPlansItem) {
    if (this.successorPlans == null) {
      this.successorPlans = new java.util.ArrayList<>();
    }
    this.successorPlans.add(successorPlansItem);
    return this;
  }

  /**
   * .
   *
   * @return successorPlans
   */
  @Schema(description = "")
  public java.util.List<BillingPlan> getSuccessorPlans() {
    return successorPlans;
  }

  /** setSuccessorPlans. */
  public void setSuccessorPlans(java.util.List<BillingPlan> successorPlans) {
    this.successorPlans = successorPlans;
  }

  /**
   * taxExemptId.
   *
   * @return AccountBillingPlanResponse
   */
  public AccountBillingPlanResponse taxExemptId(String taxExemptId) {
    this.taxExemptId = taxExemptId;
    return this;
  }

  /**
   * .
   *
   * @return taxExemptId
   */
  @Schema(description = "")
  public String getTaxExemptId() {
    return taxExemptId;
  }

  /** setTaxExemptId. */
  public void setTaxExemptId(String taxExemptId) {
    this.taxExemptId = taxExemptId;
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
    AccountBillingPlanResponse accountBillingPlanResponse = (AccountBillingPlanResponse) o;
    return Objects.equals(this.billingAddress, accountBillingPlanResponse.billingAddress)
        && Objects.equals(
            this.billingAddressIsCreditCardAddress,
            accountBillingPlanResponse.billingAddressIsCreditCardAddress)
        && Objects.equals(this.billingPlan, accountBillingPlanResponse.billingPlan)
        && Objects.equals(
            this.creditCardInformation, accountBillingPlanResponse.creditCardInformation)
        && Objects.equals(
            this.directDebitProcessorInformation,
            accountBillingPlanResponse.directDebitProcessorInformation)
        && Objects.equals(
            this.downgradePlanInformation, accountBillingPlanResponse.downgradePlanInformation)
        && Objects.equals(
            this.downgradeRequestInformation,
            accountBillingPlanResponse.downgradeRequestInformation)
        && Objects.equals(this.entityInformation, accountBillingPlanResponse.entityInformation)
        && Objects.equals(this.paymentMethod, accountBillingPlanResponse.paymentMethod)
        && Objects.equals(
            this.paymentProcessorInformation,
            accountBillingPlanResponse.paymentProcessorInformation)
        && Objects.equals(this.referralInformation, accountBillingPlanResponse.referralInformation)
        && Objects.equals(this.successorPlans, accountBillingPlanResponse.successorPlans)
        && Objects.equals(this.taxExemptId, accountBillingPlanResponse.taxExemptId);
  }

  /** Returns the HashCode. */
  @Override
  public int hashCode() {
    return Objects.hash(
        billingAddress,
        billingAddressIsCreditCardAddress,
        billingPlan,
        creditCardInformation,
        directDebitProcessorInformation,
        downgradePlanInformation,
        downgradeRequestInformation,
        entityInformation,
        paymentMethod,
        paymentProcessorInformation,
        referralInformation,
        successorPlans,
        taxExemptId);
  }

  /** Converts the given object to string. */
  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class AccountBillingPlanResponse {\n");

    sb.append("    billingAddress: ").append(toIndentedString(billingAddress)).append("\n");
    sb.append("    billingAddressIsCreditCardAddress: ")
        .append(toIndentedString(billingAddressIsCreditCardAddress))
        .append("\n");
    sb.append("    billingPlan: ").append(toIndentedString(billingPlan)).append("\n");
    sb.append("    creditCardInformation: ")
        .append(toIndentedString(creditCardInformation))
        .append("\n");
    sb.append("    directDebitProcessorInformation: ")
        .append(toIndentedString(directDebitProcessorInformation))
        .append("\n");
    sb.append("    downgradePlanInformation: ")
        .append(toIndentedString(downgradePlanInformation))
        .append("\n");
    sb.append("    downgradeRequestInformation: ")
        .append(toIndentedString(downgradeRequestInformation))
        .append("\n");
    sb.append("    entityInformation: ").append(toIndentedString(entityInformation)).append("\n");
    sb.append("    paymentMethod: ").append(toIndentedString(paymentMethod)).append("\n");
    sb.append("    paymentProcessorInformation: ")
        .append(toIndentedString(paymentProcessorInformation))
        .append("\n");
    sb.append("    referralInformation: ")
        .append(toIndentedString(referralInformation))
        .append("\n");
    sb.append("    successorPlans: ").append(toIndentedString(successorPlans)).append("\n");
    sb.append("    taxExemptId: ").append(toIndentedString(taxExemptId)).append("\n");
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
