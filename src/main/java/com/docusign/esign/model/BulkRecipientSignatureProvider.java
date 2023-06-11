package com.docusign.esign.model;

import com.docusign.esign.override.swagger.Schema;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;

/** BulkRecipientSignatureProvider. */
public class BulkRecipientSignatureProvider {
  @JsonProperty("name")
  private String name = null;

  @JsonProperty("value")
  private String value = null;

  /**
   * name.
   *
   * @return BulkRecipientSignatureProvider
   */
  public BulkRecipientSignatureProvider name(String name) {
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
   * value.
   *
   * @return BulkRecipientSignatureProvider
   */
  public BulkRecipientSignatureProvider value(String value) {
    this.value = value;
    return this;
  }

  /**
   * Specifies the value of the tab. .
   *
   * @return value
   */
  @Schema(description = "Specifies the value of the tab. ")
  public String getValue() {
    return value;
  }

  /** setValue. */
  public void setValue(String value) {
    this.value = value;
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
    BulkRecipientSignatureProvider bulkRecipientSignatureProvider =
        (BulkRecipientSignatureProvider) o;
    return Objects.equals(this.name, bulkRecipientSignatureProvider.name)
        && Objects.equals(this.value, bulkRecipientSignatureProvider.value);
  }

  /** Returns the HashCode. */
  @Override
  public int hashCode() {
    return Objects.hash(name, value);
  }

  /** Converts the given object to string. */
  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class BulkRecipientSignatureProvider {\n");

    sb.append("    name: ").append(toIndentedString(name)).append("\n");
    sb.append("    value: ").append(toIndentedString(value)).append("\n");
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
