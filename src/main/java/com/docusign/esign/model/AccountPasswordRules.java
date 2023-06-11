package com.docusign.esign.model;

import com.docusign.esign.override.swagger.Schema;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;

/** AccountPasswordRules. */
public class AccountPasswordRules {
  @JsonProperty("expirePassword")
  private String expirePassword = null;

  @JsonProperty("expirePasswordDays")
  private String expirePasswordDays = null;

  @JsonProperty("expirePasswordDaysMetadata")
  private AccountPasswordExpirePasswordDays expirePasswordDaysMetadata = null;

  @JsonProperty("lockoutDurationMinutes")
  private String lockoutDurationMinutes = null;

  @JsonProperty("lockoutDurationMinutesMetadata")
  private AccountPasswordLockoutDurationMinutes lockoutDurationMinutesMetadata = null;

  @JsonProperty("lockoutDurationType")
  private String lockoutDurationType = null;

  @JsonProperty("lockoutDurationTypeMetadata")
  private AccountPasswordLockoutDurationType lockoutDurationTypeMetadata = null;

  @JsonProperty("minimumPasswordAgeDays")
  private String minimumPasswordAgeDays = null;

  @JsonProperty("minimumPasswordAgeDaysMetadata")
  private AccountPasswordMinimumPasswordAgeDays minimumPasswordAgeDaysMetadata = null;

  @JsonProperty("minimumPasswordLength")
  private String minimumPasswordLength = null;

  @JsonProperty("minimumPasswordLengthMetadata")
  private AccountMinimumPasswordLength minimumPasswordLengthMetadata = null;

  @JsonProperty("passwordIncludeDigit")
  private String passwordIncludeDigit = null;

  @JsonProperty("passwordIncludeDigitOrSpecialCharacter")
  private String passwordIncludeDigitOrSpecialCharacter = null;

  @JsonProperty("passwordIncludeLowerCase")
  private String passwordIncludeLowerCase = null;

  @JsonProperty("passwordIncludeSpecialCharacter")
  private String passwordIncludeSpecialCharacter = null;

  @JsonProperty("passwordIncludeUpperCase")
  private String passwordIncludeUpperCase = null;

  @JsonProperty("passwordStrengthType")
  private String passwordStrengthType = null;

  @JsonProperty("passwordStrengthTypeMetadata")
  private AccountPasswordStrengthType passwordStrengthTypeMetadata = null;

  @JsonProperty("questionsRequired")
  private String questionsRequired = null;

  @JsonProperty("questionsRequiredMetadata")
  private AccountPasswordQuestionsRequired questionsRequiredMetadata = null;

  /**
   * expirePassword.
   *
   * @return AccountPasswordRules
   */
  public AccountPasswordRules expirePassword(String expirePassword) {
    this.expirePassword = expirePassword;
    return this;
  }

  /**
   * .
   *
   * @return expirePassword
   */
  @Schema(description = "")
  public String getExpirePassword() {
    return expirePassword;
  }

  /** setExpirePassword. */
  public void setExpirePassword(String expirePassword) {
    this.expirePassword = expirePassword;
  }

  /**
   * expirePasswordDays.
   *
   * @return AccountPasswordRules
   */
  public AccountPasswordRules expirePasswordDays(String expirePasswordDays) {
    this.expirePasswordDays = expirePasswordDays;
    return this;
  }

  /**
   * .
   *
   * @return expirePasswordDays
   */
  @Schema(description = "")
  public String getExpirePasswordDays() {
    return expirePasswordDays;
  }

  /** setExpirePasswordDays. */
  public void setExpirePasswordDays(String expirePasswordDays) {
    this.expirePasswordDays = expirePasswordDays;
  }

  /**
   * expirePasswordDaysMetadata.
   *
   * @return AccountPasswordRules
   */
  public AccountPasswordRules expirePasswordDaysMetadata(
      AccountPasswordExpirePasswordDays expirePasswordDaysMetadata) {
    this.expirePasswordDaysMetadata = expirePasswordDaysMetadata;
    return this;
  }

  /**
   * Metadata that indicates whether the `expirePasswordDays` property is editable. .
   *
   * @return expirePasswordDaysMetadata
   */
  @Schema(
      description =
          "Metadata that indicates whether the `expirePasswordDays` property is editable. ")
  public AccountPasswordExpirePasswordDays getExpirePasswordDaysMetadata() {
    return expirePasswordDaysMetadata;
  }

  /** setExpirePasswordDaysMetadata. */
  public void setExpirePasswordDaysMetadata(
      AccountPasswordExpirePasswordDays expirePasswordDaysMetadata) {
    this.expirePasswordDaysMetadata = expirePasswordDaysMetadata;
  }

  /**
   * lockoutDurationMinutes.
   *
   * @return AccountPasswordRules
   */
  public AccountPasswordRules lockoutDurationMinutes(String lockoutDurationMinutes) {
    this.lockoutDurationMinutes = lockoutDurationMinutes;
    return this;
  }

  /**
   * .
   *
   * @return lockoutDurationMinutes
   */
  @Schema(description = "")
  public String getLockoutDurationMinutes() {
    return lockoutDurationMinutes;
  }

  /** setLockoutDurationMinutes. */
  public void setLockoutDurationMinutes(String lockoutDurationMinutes) {
    this.lockoutDurationMinutes = lockoutDurationMinutes;
  }

  /**
   * lockoutDurationMinutesMetadata.
   *
   * @return AccountPasswordRules
   */
  public AccountPasswordRules lockoutDurationMinutesMetadata(
      AccountPasswordLockoutDurationMinutes lockoutDurationMinutesMetadata) {
    this.lockoutDurationMinutesMetadata = lockoutDurationMinutesMetadata;
    return this;
  }

  /**
   * Metadata that indicates whether the `lockoutDurationMinutes` property is editable. .
   *
   * @return lockoutDurationMinutesMetadata
   */
  @Schema(
      description =
          "Metadata that indicates whether the `lockoutDurationMinutes` property is editable. ")
  public AccountPasswordLockoutDurationMinutes getLockoutDurationMinutesMetadata() {
    return lockoutDurationMinutesMetadata;
  }

  /** setLockoutDurationMinutesMetadata. */
  public void setLockoutDurationMinutesMetadata(
      AccountPasswordLockoutDurationMinutes lockoutDurationMinutesMetadata) {
    this.lockoutDurationMinutesMetadata = lockoutDurationMinutesMetadata;
  }

  /**
   * lockoutDurationType.
   *
   * @return AccountPasswordRules
   */
  public AccountPasswordRules lockoutDurationType(String lockoutDurationType) {
    this.lockoutDurationType = lockoutDurationType;
    return this;
  }

  /**
   * .
   *
   * @return lockoutDurationType
   */
  @Schema(description = "")
  public String getLockoutDurationType() {
    return lockoutDurationType;
  }

  /** setLockoutDurationType. */
  public void setLockoutDurationType(String lockoutDurationType) {
    this.lockoutDurationType = lockoutDurationType;
  }

  /**
   * lockoutDurationTypeMetadata.
   *
   * @return AccountPasswordRules
   */
  public AccountPasswordRules lockoutDurationTypeMetadata(
      AccountPasswordLockoutDurationType lockoutDurationTypeMetadata) {
    this.lockoutDurationTypeMetadata = lockoutDurationTypeMetadata;
    return this;
  }

  /**
   * Metadata that indicates whether the `lockoutDurationType` property is editable. .
   *
   * @return lockoutDurationTypeMetadata
   */
  @Schema(
      description =
          "Metadata that indicates whether the `lockoutDurationType` property is editable. ")
  public AccountPasswordLockoutDurationType getLockoutDurationTypeMetadata() {
    return lockoutDurationTypeMetadata;
  }

  /** setLockoutDurationTypeMetadata. */
  public void setLockoutDurationTypeMetadata(
      AccountPasswordLockoutDurationType lockoutDurationTypeMetadata) {
    this.lockoutDurationTypeMetadata = lockoutDurationTypeMetadata;
  }

  /**
   * minimumPasswordAgeDays.
   *
   * @return AccountPasswordRules
   */
  public AccountPasswordRules minimumPasswordAgeDays(String minimumPasswordAgeDays) {
    this.minimumPasswordAgeDays = minimumPasswordAgeDays;
    return this;
  }

  /**
   * .
   *
   * @return minimumPasswordAgeDays
   */
  @Schema(description = "")
  public String getMinimumPasswordAgeDays() {
    return minimumPasswordAgeDays;
  }

  /** setMinimumPasswordAgeDays. */
  public void setMinimumPasswordAgeDays(String minimumPasswordAgeDays) {
    this.minimumPasswordAgeDays = minimumPasswordAgeDays;
  }

  /**
   * minimumPasswordAgeDaysMetadata.
   *
   * @return AccountPasswordRules
   */
  public AccountPasswordRules minimumPasswordAgeDaysMetadata(
      AccountPasswordMinimumPasswordAgeDays minimumPasswordAgeDaysMetadata) {
    this.minimumPasswordAgeDaysMetadata = minimumPasswordAgeDaysMetadata;
    return this;
  }

  /**
   * Metadata that indicates whether the `minimumPasswordAgeDays` property is editable. .
   *
   * @return minimumPasswordAgeDaysMetadata
   */
  @Schema(
      description =
          "Metadata that indicates whether the `minimumPasswordAgeDays` property is editable. ")
  public AccountPasswordMinimumPasswordAgeDays getMinimumPasswordAgeDaysMetadata() {
    return minimumPasswordAgeDaysMetadata;
  }

  /** setMinimumPasswordAgeDaysMetadata. */
  public void setMinimumPasswordAgeDaysMetadata(
      AccountPasswordMinimumPasswordAgeDays minimumPasswordAgeDaysMetadata) {
    this.minimumPasswordAgeDaysMetadata = minimumPasswordAgeDaysMetadata;
  }

  /**
   * minimumPasswordLength.
   *
   * @return AccountPasswordRules
   */
  public AccountPasswordRules minimumPasswordLength(String minimumPasswordLength) {
    this.minimumPasswordLength = minimumPasswordLength;
    return this;
  }

  /**
   * .
   *
   * @return minimumPasswordLength
   */
  @Schema(description = "")
  public String getMinimumPasswordLength() {
    return minimumPasswordLength;
  }

  /** setMinimumPasswordLength. */
  public void setMinimumPasswordLength(String minimumPasswordLength) {
    this.minimumPasswordLength = minimumPasswordLength;
  }

  /**
   * minimumPasswordLengthMetadata.
   *
   * @return AccountPasswordRules
   */
  public AccountPasswordRules minimumPasswordLengthMetadata(
      AccountMinimumPasswordLength minimumPasswordLengthMetadata) {
    this.minimumPasswordLengthMetadata = minimumPasswordLengthMetadata;
    return this;
  }

  /**
   * Metadata that indicates whether the `minimumPasswordLength` property is editable. .
   *
   * @return minimumPasswordLengthMetadata
   */
  @Schema(
      description =
          "Metadata that indicates whether the `minimumPasswordLength` property is editable. ")
  public AccountMinimumPasswordLength getMinimumPasswordLengthMetadata() {
    return minimumPasswordLengthMetadata;
  }

  /** setMinimumPasswordLengthMetadata. */
  public void setMinimumPasswordLengthMetadata(
      AccountMinimumPasswordLength minimumPasswordLengthMetadata) {
    this.minimumPasswordLengthMetadata = minimumPasswordLengthMetadata;
  }

  /**
   * passwordIncludeDigit.
   *
   * @return AccountPasswordRules
   */
  public AccountPasswordRules passwordIncludeDigit(String passwordIncludeDigit) {
    this.passwordIncludeDigit = passwordIncludeDigit;
    return this;
  }

  /**
   * .
   *
   * @return passwordIncludeDigit
   */
  @Schema(description = "")
  public String getPasswordIncludeDigit() {
    return passwordIncludeDigit;
  }

  /** setPasswordIncludeDigit. */
  public void setPasswordIncludeDigit(String passwordIncludeDigit) {
    this.passwordIncludeDigit = passwordIncludeDigit;
  }

  /**
   * passwordIncludeDigitOrSpecialCharacter.
   *
   * @return AccountPasswordRules
   */
  public AccountPasswordRules passwordIncludeDigitOrSpecialCharacter(
      String passwordIncludeDigitOrSpecialCharacter) {
    this.passwordIncludeDigitOrSpecialCharacter = passwordIncludeDigitOrSpecialCharacter;
    return this;
  }

  /**
   * .
   *
   * @return passwordIncludeDigitOrSpecialCharacter
   */
  @Schema(description = "")
  public String getPasswordIncludeDigitOrSpecialCharacter() {
    return passwordIncludeDigitOrSpecialCharacter;
  }

  /** setPasswordIncludeDigitOrSpecialCharacter. */
  public void setPasswordIncludeDigitOrSpecialCharacter(
      String passwordIncludeDigitOrSpecialCharacter) {
    this.passwordIncludeDigitOrSpecialCharacter = passwordIncludeDigitOrSpecialCharacter;
  }

  /**
   * passwordIncludeLowerCase.
   *
   * @return AccountPasswordRules
   */
  public AccountPasswordRules passwordIncludeLowerCase(String passwordIncludeLowerCase) {
    this.passwordIncludeLowerCase = passwordIncludeLowerCase;
    return this;
  }

  /**
   * .
   *
   * @return passwordIncludeLowerCase
   */
  @Schema(description = "")
  public String getPasswordIncludeLowerCase() {
    return passwordIncludeLowerCase;
  }

  /** setPasswordIncludeLowerCase. */
  public void setPasswordIncludeLowerCase(String passwordIncludeLowerCase) {
    this.passwordIncludeLowerCase = passwordIncludeLowerCase;
  }

  /**
   * passwordIncludeSpecialCharacter.
   *
   * @return AccountPasswordRules
   */
  public AccountPasswordRules passwordIncludeSpecialCharacter(
      String passwordIncludeSpecialCharacter) {
    this.passwordIncludeSpecialCharacter = passwordIncludeSpecialCharacter;
    return this;
  }

  /**
   * .
   *
   * @return passwordIncludeSpecialCharacter
   */
  @Schema(description = "")
  public String getPasswordIncludeSpecialCharacter() {
    return passwordIncludeSpecialCharacter;
  }

  /** setPasswordIncludeSpecialCharacter. */
  public void setPasswordIncludeSpecialCharacter(String passwordIncludeSpecialCharacter) {
    this.passwordIncludeSpecialCharacter = passwordIncludeSpecialCharacter;
  }

  /**
   * passwordIncludeUpperCase.
   *
   * @return AccountPasswordRules
   */
  public AccountPasswordRules passwordIncludeUpperCase(String passwordIncludeUpperCase) {
    this.passwordIncludeUpperCase = passwordIncludeUpperCase;
    return this;
  }

  /**
   * .
   *
   * @return passwordIncludeUpperCase
   */
  @Schema(description = "")
  public String getPasswordIncludeUpperCase() {
    return passwordIncludeUpperCase;
  }

  /** setPasswordIncludeUpperCase. */
  public void setPasswordIncludeUpperCase(String passwordIncludeUpperCase) {
    this.passwordIncludeUpperCase = passwordIncludeUpperCase;
  }

  /**
   * passwordStrengthType.
   *
   * @return AccountPasswordRules
   */
  public AccountPasswordRules passwordStrengthType(String passwordStrengthType) {
    this.passwordStrengthType = passwordStrengthType;
    return this;
  }

  /**
   * .
   *
   * @return passwordStrengthType
   */
  @Schema(description = "")
  public String getPasswordStrengthType() {
    return passwordStrengthType;
  }

  /** setPasswordStrengthType. */
  public void setPasswordStrengthType(String passwordStrengthType) {
    this.passwordStrengthType = passwordStrengthType;
  }

  /**
   * passwordStrengthTypeMetadata.
   *
   * @return AccountPasswordRules
   */
  public AccountPasswordRules passwordStrengthTypeMetadata(
      AccountPasswordStrengthType passwordStrengthTypeMetadata) {
    this.passwordStrengthTypeMetadata = passwordStrengthTypeMetadata;
    return this;
  }

  /**
   * Metadata that indicates whether the `passwordStrengthType` property is editable. .
   *
   * @return passwordStrengthTypeMetadata
   */
  @Schema(
      description =
          "Metadata that indicates whether the `passwordStrengthType` property is editable. ")
  public AccountPasswordStrengthType getPasswordStrengthTypeMetadata() {
    return passwordStrengthTypeMetadata;
  }

  /** setPasswordStrengthTypeMetadata. */
  public void setPasswordStrengthTypeMetadata(
      AccountPasswordStrengthType passwordStrengthTypeMetadata) {
    this.passwordStrengthTypeMetadata = passwordStrengthTypeMetadata;
  }

  /**
   * questionsRequired.
   *
   * @return AccountPasswordRules
   */
  public AccountPasswordRules questionsRequired(String questionsRequired) {
    this.questionsRequired = questionsRequired;
    return this;
  }

  /**
   * .
   *
   * @return questionsRequired
   */
  @Schema(description = "")
  public String getQuestionsRequired() {
    return questionsRequired;
  }

  /** setQuestionsRequired. */
  public void setQuestionsRequired(String questionsRequired) {
    this.questionsRequired = questionsRequired;
  }

  /**
   * questionsRequiredMetadata.
   *
   * @return AccountPasswordRules
   */
  public AccountPasswordRules questionsRequiredMetadata(
      AccountPasswordQuestionsRequired questionsRequiredMetadata) {
    this.questionsRequiredMetadata = questionsRequiredMetadata;
    return this;
  }

  /**
   * Metadata that indicates whether the `questionsRequired` property is editable. .
   *
   * @return questionsRequiredMetadata
   */
  @Schema(
      description =
          "Metadata that indicates whether the `questionsRequired` property is editable. ")
  public AccountPasswordQuestionsRequired getQuestionsRequiredMetadata() {
    return questionsRequiredMetadata;
  }

  /** setQuestionsRequiredMetadata. */
  public void setQuestionsRequiredMetadata(
      AccountPasswordQuestionsRequired questionsRequiredMetadata) {
    this.questionsRequiredMetadata = questionsRequiredMetadata;
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
    AccountPasswordRules accountPasswordRules = (AccountPasswordRules) o;
    return Objects.equals(this.expirePassword, accountPasswordRules.expirePassword)
        && Objects.equals(this.expirePasswordDays, accountPasswordRules.expirePasswordDays)
        && Objects.equals(
            this.expirePasswordDaysMetadata, accountPasswordRules.expirePasswordDaysMetadata)
        && Objects.equals(this.lockoutDurationMinutes, accountPasswordRules.lockoutDurationMinutes)
        && Objects.equals(
            this.lockoutDurationMinutesMetadata,
            accountPasswordRules.lockoutDurationMinutesMetadata)
        && Objects.equals(this.lockoutDurationType, accountPasswordRules.lockoutDurationType)
        && Objects.equals(
            this.lockoutDurationTypeMetadata, accountPasswordRules.lockoutDurationTypeMetadata)
        && Objects.equals(this.minimumPasswordAgeDays, accountPasswordRules.minimumPasswordAgeDays)
        && Objects.equals(
            this.minimumPasswordAgeDaysMetadata,
            accountPasswordRules.minimumPasswordAgeDaysMetadata)
        && Objects.equals(this.minimumPasswordLength, accountPasswordRules.minimumPasswordLength)
        && Objects.equals(
            this.minimumPasswordLengthMetadata, accountPasswordRules.minimumPasswordLengthMetadata)
        && Objects.equals(this.passwordIncludeDigit, accountPasswordRules.passwordIncludeDigit)
        && Objects.equals(
            this.passwordIncludeDigitOrSpecialCharacter,
            accountPasswordRules.passwordIncludeDigitOrSpecialCharacter)
        && Objects.equals(
            this.passwordIncludeLowerCase, accountPasswordRules.passwordIncludeLowerCase)
        && Objects.equals(
            this.passwordIncludeSpecialCharacter,
            accountPasswordRules.passwordIncludeSpecialCharacter)
        && Objects.equals(
            this.passwordIncludeUpperCase, accountPasswordRules.passwordIncludeUpperCase)
        && Objects.equals(this.passwordStrengthType, accountPasswordRules.passwordStrengthType)
        && Objects.equals(
            this.passwordStrengthTypeMetadata, accountPasswordRules.passwordStrengthTypeMetadata)
        && Objects.equals(this.questionsRequired, accountPasswordRules.questionsRequired)
        && Objects.equals(
            this.questionsRequiredMetadata, accountPasswordRules.questionsRequiredMetadata);
  }

  /** Returns the HashCode. */
  @Override
  public int hashCode() {
    return Objects.hash(
        expirePassword,
        expirePasswordDays,
        expirePasswordDaysMetadata,
        lockoutDurationMinutes,
        lockoutDurationMinutesMetadata,
        lockoutDurationType,
        lockoutDurationTypeMetadata,
        minimumPasswordAgeDays,
        minimumPasswordAgeDaysMetadata,
        minimumPasswordLength,
        minimumPasswordLengthMetadata,
        passwordIncludeDigit,
        passwordIncludeDigitOrSpecialCharacter,
        passwordIncludeLowerCase,
        passwordIncludeSpecialCharacter,
        passwordIncludeUpperCase,
        passwordStrengthType,
        passwordStrengthTypeMetadata,
        questionsRequired,
        questionsRequiredMetadata);
  }

  /** Converts the given object to string. */
  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class AccountPasswordRules {\n");

    sb.append("    expirePassword: ").append(toIndentedString(expirePassword)).append("\n");
    sb.append("    expirePasswordDays: ").append(toIndentedString(expirePasswordDays)).append("\n");
    sb.append("    expirePasswordDaysMetadata: ")
        .append(toIndentedString(expirePasswordDaysMetadata))
        .append("\n");
    sb.append("    lockoutDurationMinutes: ")
        .append(toIndentedString(lockoutDurationMinutes))
        .append("\n");
    sb.append("    lockoutDurationMinutesMetadata: ")
        .append(toIndentedString(lockoutDurationMinutesMetadata))
        .append("\n");
    sb.append("    lockoutDurationType: ")
        .append(toIndentedString(lockoutDurationType))
        .append("\n");
    sb.append("    lockoutDurationTypeMetadata: ")
        .append(toIndentedString(lockoutDurationTypeMetadata))
        .append("\n");
    sb.append("    minimumPasswordAgeDays: ")
        .append(toIndentedString(minimumPasswordAgeDays))
        .append("\n");
    sb.append("    minimumPasswordAgeDaysMetadata: ")
        .append(toIndentedString(minimumPasswordAgeDaysMetadata))
        .append("\n");
    sb.append("    minimumPasswordLength: ")
        .append(toIndentedString(minimumPasswordLength))
        .append("\n");
    sb.append("    minimumPasswordLengthMetadata: ")
        .append(toIndentedString(minimumPasswordLengthMetadata))
        .append("\n");
    sb.append("    passwordIncludeDigit: ")
        .append(toIndentedString(passwordIncludeDigit))
        .append("\n");
    sb.append("    passwordIncludeDigitOrSpecialCharacter: ")
        .append(toIndentedString(passwordIncludeDigitOrSpecialCharacter))
        .append("\n");
    sb.append("    passwordIncludeLowerCase: ")
        .append(toIndentedString(passwordIncludeLowerCase))
        .append("\n");
    sb.append("    passwordIncludeSpecialCharacter: ")
        .append(toIndentedString(passwordIncludeSpecialCharacter))
        .append("\n");
    sb.append("    passwordIncludeUpperCase: ")
        .append(toIndentedString(passwordIncludeUpperCase))
        .append("\n");
    sb.append("    passwordStrengthType: ")
        .append(toIndentedString(passwordStrengthType))
        .append("\n");
    sb.append("    passwordStrengthTypeMetadata: ")
        .append(toIndentedString(passwordStrengthTypeMetadata))
        .append("\n");
    sb.append("    questionsRequired: ").append(toIndentedString(questionsRequired)).append("\n");
    sb.append("    questionsRequiredMetadata: ")
        .append(toIndentedString(questionsRequiredMetadata))
        .append("\n");
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
