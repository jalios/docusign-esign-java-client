package com.docusign.esign.model;

import com.docusign.esign.override.swagger.Schema;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;

/** Contact. */
public class Contact {
  @JsonProperty("cloudProvider")
  private String cloudProvider = null;

  @JsonProperty("cloudProviderContainerId")
  private String cloudProviderContainerId = null;

  @JsonProperty("contactId")
  private String contactId = null;

  @JsonProperty("contactPhoneNumbers")
  private java.util.List<ContactPhoneNumber> contactPhoneNumbers = null;

  @JsonProperty("contactUri")
  private String contactUri = null;

  @JsonProperty("emails")
  private java.util.List<String> emails = null;

  @JsonProperty("errorDetails")
  private ErrorDetails errorDetails = null;

  @JsonProperty("isOwner")
  private Boolean isOwner = null;

  @JsonProperty("name")
  private String name = null;

  @JsonProperty("notaryContactDetails")
  private NotaryContactDetails notaryContactDetails = null;

  @JsonProperty("organization")
  private String organization = null;

  @JsonProperty("roomContactType")
  private String roomContactType = null;

  @JsonProperty("shared")
  private String shared = null;

  @JsonProperty("signingGroup")
  private String signingGroup = null;

  @JsonProperty("signingGroupName")
  private String signingGroupName = null;

  /**
   * cloudProvider.
   *
   * @return Contact
   */
  public Contact cloudProvider(String cloudProvider) {
    this.cloudProvider = cloudProvider;
    return this;
  }

  /**
   * .
   *
   * @return cloudProvider
   */
  @Schema(description = "")
  public String getCloudProvider() {
    return cloudProvider;
  }

  /** setCloudProvider. */
  public void setCloudProvider(String cloudProvider) {
    this.cloudProvider = cloudProvider;
  }

  /**
   * cloudProviderContainerId.
   *
   * @return Contact
   */
  public Contact cloudProviderContainerId(String cloudProviderContainerId) {
    this.cloudProviderContainerId = cloudProviderContainerId;
    return this;
  }

  /**
   * .
   *
   * @return cloudProviderContainerId
   */
  @Schema(description = "")
  public String getCloudProviderContainerId() {
    return cloudProviderContainerId;
  }

  /** setCloudProviderContainerId. */
  public void setCloudProviderContainerId(String cloudProviderContainerId) {
    this.cloudProviderContainerId = cloudProviderContainerId;
  }

  /**
   * contactId.
   *
   * @return Contact
   */
  public Contact contactId(String contactId) {
    this.contactId = contactId;
    return this;
  }

  /**
   * .
   *
   * @return contactId
   */
  @Schema(description = "")
  public String getContactId() {
    return contactId;
  }

  /** setContactId. */
  public void setContactId(String contactId) {
    this.contactId = contactId;
  }

  /**
   * contactPhoneNumbers.
   *
   * @return Contact
   */
  public Contact contactPhoneNumbers(java.util.List<ContactPhoneNumber> contactPhoneNumbers) {
    this.contactPhoneNumbers = contactPhoneNumbers;
    return this;
  }

  /**
   * addContactPhoneNumbersItem.
   *
   * @return Contact
   */
  public Contact addContactPhoneNumbersItem(ContactPhoneNumber contactPhoneNumbersItem) {
    if (this.contactPhoneNumbers == null) {
      this.contactPhoneNumbers = new java.util.ArrayList<>();
    }
    this.contactPhoneNumbers.add(contactPhoneNumbersItem);
    return this;
  }

  /**
   * .
   *
   * @return contactPhoneNumbers
   */
  @Schema(description = "")
  public java.util.List<ContactPhoneNumber> getContactPhoneNumbers() {
    return contactPhoneNumbers;
  }

  /** setContactPhoneNumbers. */
  public void setContactPhoneNumbers(java.util.List<ContactPhoneNumber> contactPhoneNumbers) {
    this.contactPhoneNumbers = contactPhoneNumbers;
  }

  /**
   * contactUri.
   *
   * @return Contact
   */
  public Contact contactUri(String contactUri) {
    this.contactUri = contactUri;
    return this;
  }

  /**
   * .
   *
   * @return contactUri
   */
  @Schema(description = "")
  public String getContactUri() {
    return contactUri;
  }

  /** setContactUri. */
  public void setContactUri(String contactUri) {
    this.contactUri = contactUri;
  }

  /**
   * emails.
   *
   * @return Contact
   */
  public Contact emails(java.util.List<String> emails) {
    this.emails = emails;
    return this;
  }

  /**
   * addEmailsItem.
   *
   * @return Contact
   */
  public Contact addEmailsItem(String emailsItem) {
    if (this.emails == null) {
      this.emails = new java.util.ArrayList<>();
    }
    this.emails.add(emailsItem);
    return this;
  }

  /**
   * .
   *
   * @return emails
   */
  @Schema(description = "")
  public java.util.List<String> getEmails() {
    return emails;
  }

  /** setEmails. */
  public void setEmails(java.util.List<String> emails) {
    this.emails = emails;
  }

  /**
   * errorDetails.
   *
   * @return Contact
   */
  public Contact errorDetails(ErrorDetails errorDetails) {
    this.errorDetails = errorDetails;
    return this;
  }

  /**
   * Array or errors..
   *
   * @return errorDetails
   */
  @Schema(description = "Array or errors.")
  public ErrorDetails getErrorDetails() {
    return errorDetails;
  }

  /** setErrorDetails. */
  public void setErrorDetails(ErrorDetails errorDetails) {
    this.errorDetails = errorDetails;
  }

  /**
   * isOwner.
   *
   * @return Contact
   */
  public Contact isOwner(Boolean isOwner) {
    this.isOwner = isOwner;
    return this;
  }

  /**
   * .
   *
   * @return isOwner
   */
  @Schema(description = "")
  public Boolean isIsOwner() {
    return isOwner;
  }

  /** setIsOwner. */
  public void setIsOwner(Boolean isOwner) {
    this.isOwner = isOwner;
  }

  /**
   * name.
   *
   * @return Contact
   */
  public Contact name(String name) {
    this.name = name;
    return this;
  }

  /**
   * .
   *
   * @return name
   */
  @Schema(description = "")
  public String getName() {
    return name;
  }

  /** setName. */
  public void setName(String name) {
    this.name = name;
  }

  /**
   * notaryContactDetails.
   *
   * @return Contact
   */
  public Contact notaryContactDetails(NotaryContactDetails notaryContactDetails) {
    this.notaryContactDetails = notaryContactDetails;
    return this;
  }

  /**
   * .
   *
   * @return notaryContactDetails
   */
  @Schema(description = "")
  public NotaryContactDetails getNotaryContactDetails() {
    return notaryContactDetails;
  }

  /** setNotaryContactDetails. */
  public void setNotaryContactDetails(NotaryContactDetails notaryContactDetails) {
    this.notaryContactDetails = notaryContactDetails;
  }

  /**
   * organization.
   *
   * @return Contact
   */
  public Contact organization(String organization) {
    this.organization = organization;
    return this;
  }

  /**
   * .
   *
   * @return organization
   */
  @Schema(description = "")
  public String getOrganization() {
    return organization;
  }

  /** setOrganization. */
  public void setOrganization(String organization) {
    this.organization = organization;
  }

  /**
   * roomContactType.
   *
   * @return Contact
   */
  public Contact roomContactType(String roomContactType) {
    this.roomContactType = roomContactType;
    return this;
  }

  /**
   * .
   *
   * @return roomContactType
   */
  @Schema(description = "")
  public String getRoomContactType() {
    return roomContactType;
  }

  /** setRoomContactType. */
  public void setRoomContactType(String roomContactType) {
    this.roomContactType = roomContactType;
  }

  /**
   * shared.
   *
   * @return Contact
   */
  public Contact shared(String shared) {
    this.shared = shared;
    return this;
  }

  /**
   * When set to **true**, this custom tab is shared..
   *
   * @return shared
   */
  @Schema(description = "When set to **true**, this custom tab is shared.")
  public String getShared() {
    return shared;
  }

  /** setShared. */
  public void setShared(String shared) {
    this.shared = shared;
  }

  /**
   * signingGroup.
   *
   * @return Contact
   */
  public Contact signingGroup(String signingGroup) {
    this.signingGroup = signingGroup;
    return this;
  }

  /**
   * .
   *
   * @return signingGroup
   */
  @Schema(description = "")
  public String getSigningGroup() {
    return signingGroup;
  }

  /** setSigningGroup. */
  public void setSigningGroup(String signingGroup) {
    this.signingGroup = signingGroup;
  }

  /**
   * signingGroupName.
   *
   * @return Contact
   */
  public Contact signingGroupName(String signingGroupName) {
    this.signingGroupName = signingGroupName;
    return this;
  }

  /**
   * The display name for the signing group. Maximum Length: 100 characters. .
   *
   * @return signingGroupName
   */
  @Schema(
      description = "The display name for the signing group.   Maximum Length: 100 characters. ")
  public String getSigningGroupName() {
    return signingGroupName;
  }

  /** setSigningGroupName. */
  public void setSigningGroupName(String signingGroupName) {
    this.signingGroupName = signingGroupName;
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
    Contact contact = (Contact) o;
    return Objects.equals(this.cloudProvider, contact.cloudProvider)
        && Objects.equals(this.cloudProviderContainerId, contact.cloudProviderContainerId)
        && Objects.equals(this.contactId, contact.contactId)
        && Objects.equals(this.contactPhoneNumbers, contact.contactPhoneNumbers)
        && Objects.equals(this.contactUri, contact.contactUri)
        && Objects.equals(this.emails, contact.emails)
        && Objects.equals(this.errorDetails, contact.errorDetails)
        && Objects.equals(this.isOwner, contact.isOwner)
        && Objects.equals(this.name, contact.name)
        && Objects.equals(this.notaryContactDetails, contact.notaryContactDetails)
        && Objects.equals(this.organization, contact.organization)
        && Objects.equals(this.roomContactType, contact.roomContactType)
        && Objects.equals(this.shared, contact.shared)
        && Objects.equals(this.signingGroup, contact.signingGroup)
        && Objects.equals(this.signingGroupName, contact.signingGroupName);
  }

  /** Returns the HashCode. */
  @Override
  public int hashCode() {
    return Objects.hash(
        cloudProvider,
        cloudProviderContainerId,
        contactId,
        contactPhoneNumbers,
        contactUri,
        emails,
        errorDetails,
        isOwner,
        name,
        notaryContactDetails,
        organization,
        roomContactType,
        shared,
        signingGroup,
        signingGroupName);
  }

  /** Converts the given object to string. */
  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class Contact {\n");

    sb.append("    cloudProvider: ").append(toIndentedString(cloudProvider)).append("\n");
    sb.append("    cloudProviderContainerId: ")
        .append(toIndentedString(cloudProviderContainerId))
        .append("\n");
    sb.append("    contactId: ").append(toIndentedString(contactId)).append("\n");
    sb.append("    contactPhoneNumbers: ")
        .append(toIndentedString(contactPhoneNumbers))
        .append("\n");
    sb.append("    contactUri: ").append(toIndentedString(contactUri)).append("\n");
    sb.append("    emails: ").append(toIndentedString(emails)).append("\n");
    sb.append("    errorDetails: ").append(toIndentedString(errorDetails)).append("\n");
    sb.append("    isOwner: ").append(toIndentedString(isOwner)).append("\n");
    sb.append("    name: ").append(toIndentedString(name)).append("\n");
    sb.append("    notaryContactDetails: ")
        .append(toIndentedString(notaryContactDetails))
        .append("\n");
    sb.append("    organization: ").append(toIndentedString(organization)).append("\n");
    sb.append("    roomContactType: ").append(toIndentedString(roomContactType)).append("\n");
    sb.append("    shared: ").append(toIndentedString(shared)).append("\n");
    sb.append("    signingGroup: ").append(toIndentedString(signingGroup)).append("\n");
    sb.append("    signingGroupName: ").append(toIndentedString(signingGroupName)).append("\n");
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
