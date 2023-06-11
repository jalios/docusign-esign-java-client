package com.docusign.esign.model;

import com.docusign.esign.override.swagger.Schema;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;

/** DocGenFormFieldResponse. */
public class DocGenFormFieldResponse {
  @JsonProperty("docGenFormFields")
  private java.util.List<DocGenFormFields> docGenFormFields = null;

  @JsonProperty("errorDetails")
  private ErrorDetails errorDetails = null;

  /**
   * docGenFormFields.
   *
   * @return DocGenFormFieldResponse
   */
  public DocGenFormFieldResponse docGenFormFields(
      java.util.List<DocGenFormFields> docGenFormFields) {
    this.docGenFormFields = docGenFormFields;
    return this;
  }

  /**
   * addDocGenFormFieldsItem.
   *
   * @return DocGenFormFieldResponse
   */
  public DocGenFormFieldResponse addDocGenFormFieldsItem(DocGenFormFields docGenFormFieldsItem) {
    if (this.docGenFormFields == null) {
      this.docGenFormFields = new java.util.ArrayList<>();
    }
    this.docGenFormFields.add(docGenFormFieldsItem);
    return this;
  }

  /**
   * .
   *
   * @return docGenFormFields
   */
  @Schema(description = "")
  public java.util.List<DocGenFormFields> getDocGenFormFields() {
    return docGenFormFields;
  }

  /** setDocGenFormFields. */
  public void setDocGenFormFields(java.util.List<DocGenFormFields> docGenFormFields) {
    this.docGenFormFields = docGenFormFields;
  }

  /**
   * errorDetails.
   *
   * @return DocGenFormFieldResponse
   */
  public DocGenFormFieldResponse errorDetails(ErrorDetails errorDetails) {
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
    DocGenFormFieldResponse docGenFormFieldResponse = (DocGenFormFieldResponse) o;
    return Objects.equals(this.docGenFormFields, docGenFormFieldResponse.docGenFormFields)
        && Objects.equals(this.errorDetails, docGenFormFieldResponse.errorDetails);
  }

  /** Returns the HashCode. */
  @Override
  public int hashCode() {
    return Objects.hash(docGenFormFields, errorDetails);
  }

  /** Converts the given object to string. */
  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class DocGenFormFieldResponse {\n");

    sb.append("    docGenFormFields: ").append(toIndentedString(docGenFormFields)).append("\n");
    sb.append("    errorDetails: ").append(toIndentedString(errorDetails)).append("\n");
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
