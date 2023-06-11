package com.docusign.esign.model;

import com.docusign.esign.override.swagger.Schema;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;

/** Use this object to create a filtered view of the items in a folder.. */
@Schema(description = "Use this object to create a filtered view of the items in a folder.")
public class Filter {
  @JsonProperty("actionRequired")
  private String actionRequired = null;

  @JsonProperty("expires")
  private String expires = null;

  @JsonProperty("folderIds")
  private String folderIds = null;

  @JsonProperty("fromDateTime")
  private String fromDateTime = null;

  @JsonProperty("isTemplate")
  private String isTemplate = null;

  @JsonProperty("order")
  private String order = null;

  @JsonProperty("orderBy")
  private String orderBy = null;

  @JsonProperty("searchTarget")
  private String searchTarget = null;

  @JsonProperty("searchText")
  private String searchText = null;

  @JsonProperty("status")
  private String status = null;

  @JsonProperty("toDateTime")
  private String toDateTime = null;

  /**
   * actionRequired.
   *
   * @return Filter
   */
  public Filter actionRequired(String actionRequired) {
    this.actionRequired = actionRequired;
    return this;
  }

  /**
   * Access token information..
   *
   * @return actionRequired
   */
  @Schema(description = "Access token information.")
  public String getActionRequired() {
    return actionRequired;
  }

  /** setActionRequired. */
  public void setActionRequired(String actionRequired) {
    this.actionRequired = actionRequired;
  }

  /**
   * expires.
   *
   * @return Filter
   */
  public Filter expires(String expires) {
    this.expires = expires;
    return this;
  }

  /**
   * .
   *
   * @return expires
   */
  @Schema(description = "")
  public String getExpires() {
    return expires;
  }

  /** setExpires. */
  public void setExpires(String expires) {
    this.expires = expires;
  }

  /**
   * folderIds.
   *
   * @return Filter
   */
  public Filter folderIds(String folderIds) {
    this.folderIds = folderIds;
    return this;
  }

  /**
   * .
   *
   * @return folderIds
   */
  @Schema(description = "")
  public String getFolderIds() {
    return folderIds;
  }

  /** setFolderIds. */
  public void setFolderIds(String folderIds) {
    this.folderIds = folderIds;
  }

  /**
   * fromDateTime.
   *
   * @return Filter
   */
  public Filter fromDateTime(String fromDateTime) {
    this.fromDateTime = fromDateTime;
    return this;
  }

  /**
   * .
   *
   * @return fromDateTime
   */
  @Schema(description = "")
  public String getFromDateTime() {
    return fromDateTime;
  }

  /** setFromDateTime. */
  public void setFromDateTime(String fromDateTime) {
    this.fromDateTime = fromDateTime;
  }

  /**
   * isTemplate.
   *
   * @return Filter
   */
  public Filter isTemplate(String isTemplate) {
    this.isTemplate = isTemplate;
    return this;
  }

  /**
   * .
   *
   * @return isTemplate
   */
  @Schema(description = "")
  public String getIsTemplate() {
    return isTemplate;
  }

  /** setIsTemplate. */
  public void setIsTemplate(String isTemplate) {
    this.isTemplate = isTemplate;
  }

  /**
   * order.
   *
   * @return Filter
   */
  public Filter order(String order) {
    this.order = order;
    return this;
  }

  /**
   * .
   *
   * @return order
   */
  @Schema(description = "")
  public String getOrder() {
    return order;
  }

  /** setOrder. */
  public void setOrder(String order) {
    this.order = order;
  }

  /**
   * orderBy.
   *
   * @return Filter
   */
  public Filter orderBy(String orderBy) {
    this.orderBy = orderBy;
    return this;
  }

  /**
   * .
   *
   * @return orderBy
   */
  @Schema(description = "")
  public String getOrderBy() {
    return orderBy;
  }

  /** setOrderBy. */
  public void setOrderBy(String orderBy) {
    this.orderBy = orderBy;
  }

  /**
   * searchTarget.
   *
   * @return Filter
   */
  public Filter searchTarget(String searchTarget) {
    this.searchTarget = searchTarget;
    return this;
  }

  /**
   * .
   *
   * @return searchTarget
   */
  @Schema(description = "")
  public String getSearchTarget() {
    return searchTarget;
  }

  /** setSearchTarget. */
  public void setSearchTarget(String searchTarget) {
    this.searchTarget = searchTarget;
  }

  /**
   * searchText.
   *
   * @return Filter
   */
  public Filter searchText(String searchText) {
    this.searchText = searchText;
    return this;
  }

  /**
   * .
   *
   * @return searchText
   */
  @Schema(description = "")
  public String getSearchText() {
    return searchText;
  }

  /** setSearchText. */
  public void setSearchText(String searchText) {
    this.searchText = searchText;
  }

  /**
   * status.
   *
   * @return Filter
   */
  public Filter status(String status) {
    this.status = status;
    return this;
  }

  /**
   * Indicates the envelope status. Valid values are: * sent - The envelope is sent to the
   * recipients. * created - The envelope is saved as a draft and can be modified and sent later..
   *
   * @return status
   */
  @Schema(
      description =
          "Indicates the envelope status. Valid values are:  * sent - The envelope is sent to the recipients.  * created - The envelope is saved as a draft and can be modified and sent later.")
  public String getStatus() {
    return status;
  }

  /** setStatus. */
  public void setStatus(String status) {
    this.status = status;
  }

  /**
   * toDateTime.
   *
   * @return Filter
   */
  public Filter toDateTime(String toDateTime) {
    this.toDateTime = toDateTime;
    return this;
  }

  /**
   * Must be set to \"bearer\"..
   *
   * @return toDateTime
   */
  @Schema(description = "Must be set to \"bearer\".")
  public String getToDateTime() {
    return toDateTime;
  }

  /** setToDateTime. */
  public void setToDateTime(String toDateTime) {
    this.toDateTime = toDateTime;
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
    Filter filter = (Filter) o;
    return Objects.equals(this.actionRequired, filter.actionRequired)
        && Objects.equals(this.expires, filter.expires)
        && Objects.equals(this.folderIds, filter.folderIds)
        && Objects.equals(this.fromDateTime, filter.fromDateTime)
        && Objects.equals(this.isTemplate, filter.isTemplate)
        && Objects.equals(this.order, filter.order)
        && Objects.equals(this.orderBy, filter.orderBy)
        && Objects.equals(this.searchTarget, filter.searchTarget)
        && Objects.equals(this.searchText, filter.searchText)
        && Objects.equals(this.status, filter.status)
        && Objects.equals(this.toDateTime, filter.toDateTime);
  }

  /** Returns the HashCode. */
  @Override
  public int hashCode() {
    return Objects.hash(
        actionRequired,
        expires,
        folderIds,
        fromDateTime,
        isTemplate,
        order,
        orderBy,
        searchTarget,
        searchText,
        status,
        toDateTime);
  }

  /** Converts the given object to string. */
  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class Filter {\n");

    sb.append("    actionRequired: ").append(toIndentedString(actionRequired)).append("\n");
    sb.append("    expires: ").append(toIndentedString(expires)).append("\n");
    sb.append("    folderIds: ").append(toIndentedString(folderIds)).append("\n");
    sb.append("    fromDateTime: ").append(toIndentedString(fromDateTime)).append("\n");
    sb.append("    isTemplate: ").append(toIndentedString(isTemplate)).append("\n");
    sb.append("    order: ").append(toIndentedString(order)).append("\n");
    sb.append("    orderBy: ").append(toIndentedString(orderBy)).append("\n");
    sb.append("    searchTarget: ").append(toIndentedString(searchTarget)).append("\n");
    sb.append("    searchText: ").append(toIndentedString(searchText)).append("\n");
    sb.append("    status: ").append(toIndentedString(status)).append("\n");
    sb.append("    toDateTime: ").append(toIndentedString(toDateTime)).append("\n");
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
