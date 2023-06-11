package com.docusign.esign.model;

import com.docusign.esign.override.swagger.Schema;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;

/**
 * The URIs for retrieving the logos that are associated with the brand. These are read-only
 * properties that provide a URI to logos in use. To update a logo use [AccountBrands:
 * updateLogo](/docs/esign-rest-api/reference/accounts/accountbrands/updatelogo/). .
 */
@Schema(
    description =
        "The URIs for retrieving the logos that are associated with the brand.  These are read-only properties that provide a URI to logos in use. To update a logo use [AccountBrands: updateLogo](/docs/esign-rest-api/reference/accounts/accountbrands/updatelogo/). ")
public class BrandLogos {
  @JsonProperty("email")
  private String email = null;

  @JsonProperty("primary")
  private String primary = null;

  @JsonProperty("secondary")
  private String secondary = null;

  /**
   * email.
   *
   * @return BrandLogos
   */
  public BrandLogos email(String email) {
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
   * primary.
   *
   * @return BrandLogos
   */
  public BrandLogos primary(String primary) {
    this.primary = primary;
    return this;
  }

  /**
   * .
   *
   * @return primary
   */
  @Schema(description = "")
  public String getPrimary() {
    return primary;
  }

  /** setPrimary. */
  public void setPrimary(String primary) {
    this.primary = primary;
  }

  /**
   * secondary.
   *
   * @return BrandLogos
   */
  public BrandLogos secondary(String secondary) {
    this.secondary = secondary;
    return this;
  }

  /**
   * .
   *
   * @return secondary
   */
  @Schema(description = "")
  public String getSecondary() {
    return secondary;
  }

  /** setSecondary. */
  public void setSecondary(String secondary) {
    this.secondary = secondary;
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
    BrandLogos brandLogos = (BrandLogos) o;
    return Objects.equals(this.email, brandLogos.email)
        && Objects.equals(this.primary, brandLogos.primary)
        && Objects.equals(this.secondary, brandLogos.secondary);
  }

  /** Returns the HashCode. */
  @Override
  public int hashCode() {
    return Objects.hash(email, primary, secondary);
  }

  /** Converts the given object to string. */
  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class BrandLogos {\n");

    sb.append("    email: ").append(toIndentedString(email)).append("\n");
    sb.append("    primary: ").append(toIndentedString(primary)).append("\n");
    sb.append("    secondary: ").append(toIndentedString(secondary)).append("\n");
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
