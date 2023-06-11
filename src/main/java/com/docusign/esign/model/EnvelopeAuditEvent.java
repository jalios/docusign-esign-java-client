package com.docusign.esign.model;

import com.docusign.esign.override.swagger.Schema;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;

/** EnvelopeAuditEvent. */
public class EnvelopeAuditEvent {
  @JsonProperty("eventFields")
  private java.util.List<NameValue> eventFields = null;

  /**
   * eventFields.
   *
   * @return EnvelopeAuditEvent
   */
  public EnvelopeAuditEvent eventFields(java.util.List<NameValue> eventFields) {
    this.eventFields = eventFields;
    return this;
  }

  /**
   * addEventFieldsItem.
   *
   * @return EnvelopeAuditEvent
   */
  public EnvelopeAuditEvent addEventFieldsItem(NameValue eventFieldsItem) {
    if (this.eventFields == null) {
      this.eventFields = new java.util.ArrayList<>();
    }
    this.eventFields.add(eventFieldsItem);
    return this;
  }

  /**
   * .
   *
   * @return eventFields
   */
  @Schema(description = "")
  public java.util.List<NameValue> getEventFields() {
    return eventFields;
  }

  /** setEventFields. */
  public void setEventFields(java.util.List<NameValue> eventFields) {
    this.eventFields = eventFields;
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
    EnvelopeAuditEvent envelopeAuditEvent = (EnvelopeAuditEvent) o;
    return Objects.equals(this.eventFields, envelopeAuditEvent.eventFields);
  }

  /** Returns the HashCode. */
  @Override
  public int hashCode() {
    return Objects.hash(eventFields);
  }

  /** Converts the given object to string. */
  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class EnvelopeAuditEvent {\n");

    sb.append("    eventFields: ").append(toIndentedString(eventFields)).append("\n");
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
