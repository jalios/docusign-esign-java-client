package com.docusign.esign.model;

import com.docusign.esign.override.swagger.Schema;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;

/** NotificationDefaults. */
public class NotificationDefaults {
  @JsonProperty("apiEmailNotifications")
  private NotificationDefaultSettings apiEmailNotifications = null;

  @JsonProperty("emailNotifications")
  private NotificationDefaultSettings emailNotifications = null;

  /**
   * apiEmailNotifications.
   *
   * @return NotificationDefaults
   */
  public NotificationDefaults apiEmailNotifications(
      NotificationDefaultSettings apiEmailNotifications) {
    this.apiEmailNotifications = apiEmailNotifications;
    return this;
  }

  /**
   * The default notification settings for envelopes sent by using the console..
   *
   * @return apiEmailNotifications
   */
  @Schema(
      description = "The default notification settings for envelopes sent by using the console.")
  public NotificationDefaultSettings getApiEmailNotifications() {
    return apiEmailNotifications;
  }

  /** setApiEmailNotifications. */
  public void setApiEmailNotifications(NotificationDefaultSettings apiEmailNotifications) {
    this.apiEmailNotifications = apiEmailNotifications;
  }

  /**
   * emailNotifications.
   *
   * @return NotificationDefaults
   */
  public NotificationDefaults emailNotifications(NotificationDefaultSettings emailNotifications) {
    this.emailNotifications = emailNotifications;
    return this;
  }

  /**
   * The default notification settings for envelopes sent by using the API..
   *
   * @return emailNotifications
   */
  @Schema(description = "The default notification settings for envelopes sent by using the API.")
  public NotificationDefaultSettings getEmailNotifications() {
    return emailNotifications;
  }

  /** setEmailNotifications. */
  public void setEmailNotifications(NotificationDefaultSettings emailNotifications) {
    this.emailNotifications = emailNotifications;
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
    NotificationDefaults notificationDefaults = (NotificationDefaults) o;
    return Objects.equals(this.apiEmailNotifications, notificationDefaults.apiEmailNotifications)
        && Objects.equals(this.emailNotifications, notificationDefaults.emailNotifications);
  }

  /** Returns the HashCode. */
  @Override
  public int hashCode() {
    return Objects.hash(apiEmailNotifications, emailNotifications);
  }

  /** Converts the given object to string. */
  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class NotificationDefaults {\n");

    sb.append("    apiEmailNotifications: ")
        .append(toIndentedString(apiEmailNotifications))
        .append("\n");
    sb.append("    emailNotifications: ").append(toIndentedString(emailNotifications)).append("\n");
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
