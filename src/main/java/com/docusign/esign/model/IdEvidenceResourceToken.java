package com.docusign.esign.model;

import com.docusign.esign.override.swagger.Schema;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;

/** IdEvidenceResourceToken. */
public class IdEvidenceResourceToken {
  @JsonProperty("proofBaseURI")
  private String proofBaseURI = null;

  @JsonProperty("resourceToken")
  private String resourceToken = null;

  /**
   * proofBaseURI.
   *
   * @return IdEvidenceResourceToken
   */
  public IdEvidenceResourceToken proofBaseURI(String proofBaseURI) {
    this.proofBaseURI = proofBaseURI;
    return this;
  }

  /**
   * .
   *
   * @return proofBaseURI
   */
  @Schema(description = "")
  public String getProofBaseURI() {
    return proofBaseURI;
  }

  /** setProofBaseURI. */
  public void setProofBaseURI(String proofBaseURI) {
    this.proofBaseURI = proofBaseURI;
  }

  /**
   * resourceToken.
   *
   * @return IdEvidenceResourceToken
   */
  public IdEvidenceResourceToken resourceToken(String resourceToken) {
    this.resourceToken = resourceToken;
    return this;
  }

  /**
   * .
   *
   * @return resourceToken
   */
  @Schema(description = "")
  public String getResourceToken() {
    return resourceToken;
  }

  /** setResourceToken. */
  public void setResourceToken(String resourceToken) {
    this.resourceToken = resourceToken;
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
    IdEvidenceResourceToken idEvidenceResourceToken = (IdEvidenceResourceToken) o;
    return Objects.equals(this.proofBaseURI, idEvidenceResourceToken.proofBaseURI)
        && Objects.equals(this.resourceToken, idEvidenceResourceToken.resourceToken);
  }

  /** Returns the HashCode. */
  @Override
  public int hashCode() {
    return Objects.hash(proofBaseURI, resourceToken);
  }

  /** Converts the given object to string. */
  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class IdEvidenceResourceToken {\n");

    sb.append("    proofBaseURI: ").append(toIndentedString(proofBaseURI)).append("\n");
    sb.append("    resourceToken: ").append(toIndentedString(resourceToken)).append("\n");
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
