package com.docusign.esign.model;

import com.docusign.esign.override.swagger.Schema;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;

/** NotaryCertificate */
public class NotaryCertificate {
  @JsonProperty("anchorAllowWhiteSpaceInCharacters")
  private String anchorAllowWhiteSpaceInCharacters = null;

  @JsonProperty("anchorAllowWhiteSpaceInCharactersMetadata")
  private PropertyMetadata anchorAllowWhiteSpaceInCharactersMetadata = null;

  @JsonProperty("anchorCaseSensitive")
  private String anchorCaseSensitive = null;

  @JsonProperty("anchorCaseSensitiveMetadata")
  private PropertyMetadata anchorCaseSensitiveMetadata = null;

  @JsonProperty("anchorHorizontalAlignment")
  private String anchorHorizontalAlignment = null;

  @JsonProperty("anchorHorizontalAlignmentMetadata")
  private PropertyMetadata anchorHorizontalAlignmentMetadata = null;

  @JsonProperty("anchorIgnoreIfNotPresent")
  private String anchorIgnoreIfNotPresent = null;

  @JsonProperty("anchorIgnoreIfNotPresentMetadata")
  private PropertyMetadata anchorIgnoreIfNotPresentMetadata = null;

  @JsonProperty("anchorMatchWholeWord")
  private String anchorMatchWholeWord = null;

  @JsonProperty("anchorMatchWholeWordMetadata")
  private PropertyMetadata anchorMatchWholeWordMetadata = null;

  @JsonProperty("anchorString")
  private String anchorString = null;

  @JsonProperty("anchorStringMetadata")
  private PropertyMetadata anchorStringMetadata = null;

  @JsonProperty("anchorTabProcessorVersion")
  private String anchorTabProcessorVersion = null;

  @JsonProperty("anchorTabProcessorVersionMetadata")
  private PropertyMetadata anchorTabProcessorVersionMetadata = null;

  @JsonProperty("anchorUnits")
  private String anchorUnits = null;

  @JsonProperty("anchorUnitsMetadata")
  private PropertyMetadata anchorUnitsMetadata = null;

  @JsonProperty("anchorXOffset")
  private String anchorXOffset = null;

  @JsonProperty("anchorXOffsetMetadata")
  private PropertyMetadata anchorXOffsetMetadata = null;

  @JsonProperty("anchorYOffset")
  private String anchorYOffset = null;

  @JsonProperty("anchorYOffsetMetadata")
  private PropertyMetadata anchorYOffsetMetadata = null;

  @JsonProperty("conditionalParentLabel")
  private String conditionalParentLabel = null;

  @JsonProperty("conditionalParentLabelMetadata")
  private PropertyMetadata conditionalParentLabelMetadata = null;

  @JsonProperty("conditionalParentValue")
  private String conditionalParentValue = null;

  @JsonProperty("conditionalParentValueMetadata")
  private PropertyMetadata conditionalParentValueMetadata = null;

  @JsonProperty("customTabId")
  private String customTabId = null;

  @JsonProperty("customTabIdMetadata")
  private PropertyMetadata customTabIdMetadata = null;

  @JsonProperty("documentId")
  private String documentId = null;

  @JsonProperty("documentIdMetadata")
  private PropertyMetadata documentIdMetadata = null;

  @JsonProperty("errorDetails")
  private ErrorDetails errorDetails = null;

  @JsonProperty("formOrder")
  private String formOrder = null;

  @JsonProperty("formOrderMetadata")
  private PropertyMetadata formOrderMetadata = null;

  @JsonProperty("formPageLabel")
  private String formPageLabel = null;

  @JsonProperty("formPageLabelMetadata")
  private PropertyMetadata formPageLabelMetadata = null;

  @JsonProperty("formPageNumber")
  private String formPageNumber = null;

  @JsonProperty("formPageNumberMetadata")
  private PropertyMetadata formPageNumberMetadata = null;

  @JsonProperty("height")
  private String height = null;

  @JsonProperty("heightMetadata")
  private PropertyMetadata heightMetadata = null;

  @JsonProperty("locked")
  private String locked = null;

  @JsonProperty("lockedMetadata")
  private PropertyMetadata lockedMetadata = null;

  @JsonProperty("mergeField")
  private MergeField mergeField = null;

  @JsonProperty("mergeFieldXml")
  private String mergeFieldXml = null;

  @JsonProperty("pageNumber")
  private String pageNumber = null;

  @JsonProperty("pageNumberMetadata")
  private PropertyMetadata pageNumberMetadata = null;

  @JsonProperty("recipientId")
  private String recipientId = null;

  @JsonProperty("recipientIdGuid")
  private String recipientIdGuid = null;

  @JsonProperty("recipientIdGuidMetadata")
  private PropertyMetadata recipientIdGuidMetadata = null;

  @JsonProperty("recipientIdMetadata")
  private PropertyMetadata recipientIdMetadata = null;

  @JsonProperty("required")
  private String required = null;

  @JsonProperty("requiredMetadata")
  private PropertyMetadata requiredMetadata = null;

  @JsonProperty("smartContractInformation")
  private SmartContractInformation smartContractInformation = null;

  @JsonProperty("status")
  private String status = null;

  @JsonProperty("statusMetadata")
  private PropertyMetadata statusMetadata = null;

  @JsonProperty("tabGroupLabels")
  private java.util.List<String> tabGroupLabels = null;

  @JsonProperty("tabGroupLabelsMetadata")
  private PropertyMetadata tabGroupLabelsMetadata = null;

  @JsonProperty("tabId")
  private String tabId = null;

  @JsonProperty("tabIdMetadata")
  private PropertyMetadata tabIdMetadata = null;

  @JsonProperty("tabLabelMetadata")
  private PropertyMetadata tabLabelMetadata = null;

  @JsonProperty("tabOrder")
  private String tabOrder = null;

  @JsonProperty("tabOrderMetadata")
  private PropertyMetadata tabOrderMetadata = null;

  @JsonProperty("tabType")
  private String tabType = null;

  @JsonProperty("tabTypeMetadata")
  private PropertyMetadata tabTypeMetadata = null;

  @JsonProperty("templateLocked")
  private String templateLocked = null;

  @JsonProperty("templateLockedMetadata")
  private PropertyMetadata templateLockedMetadata = null;

  @JsonProperty("templateRequired")
  private String templateRequired = null;

  @JsonProperty("templateRequiredMetadata")
  private PropertyMetadata templateRequiredMetadata = null;

  @JsonProperty("tooltip")
  private String tooltip = null;

  @JsonProperty("toolTipMetadata")
  private PropertyMetadata toolTipMetadata = null;

  @JsonProperty("width")
  private String width = null;

  @JsonProperty("widthMetadata")
  private PropertyMetadata widthMetadata = null;

  @JsonProperty("xPosition")
  private String xPosition = null;

  @JsonProperty("xPositionMetadata")
  private PropertyMetadata xPositionMetadata = null;

  @JsonProperty("yPosition")
  private String yPosition = null;

  @JsonProperty("yPositionMetadata")
  private PropertyMetadata yPositionMetadata = null;

  public NotaryCertificate anchorAllowWhiteSpaceInCharacters(
      String anchorAllowWhiteSpaceInCharacters) {
    this.anchorAllowWhiteSpaceInCharacters = anchorAllowWhiteSpaceInCharacters;
    return this;
  }

  /** @return anchorAllowWhiteSpaceInCharacters */
  @Schema(description = "")
  public String getAnchorAllowWhiteSpaceInCharacters() {
    return anchorAllowWhiteSpaceInCharacters;
  }

  public void setAnchorAllowWhiteSpaceInCharacters(String anchorAllowWhiteSpaceInCharacters) {
    this.anchorAllowWhiteSpaceInCharacters = anchorAllowWhiteSpaceInCharacters;
  }

  public NotaryCertificate anchorAllowWhiteSpaceInCharactersMetadata(
      PropertyMetadata anchorAllowWhiteSpaceInCharactersMetadata) {
    this.anchorAllowWhiteSpaceInCharactersMetadata = anchorAllowWhiteSpaceInCharactersMetadata;
    return this;
  }

  /**
   * Get anchorAllowWhiteSpaceInCharactersMetadata
   *
   * @return anchorAllowWhiteSpaceInCharactersMetadata
   */
  @Schema(description = "")
  public PropertyMetadata getAnchorAllowWhiteSpaceInCharactersMetadata() {
    return anchorAllowWhiteSpaceInCharactersMetadata;
  }

  public void setAnchorAllowWhiteSpaceInCharactersMetadata(
      PropertyMetadata anchorAllowWhiteSpaceInCharactersMetadata) {
    this.anchorAllowWhiteSpaceInCharactersMetadata = anchorAllowWhiteSpaceInCharactersMetadata;
  }

  public NotaryCertificate anchorCaseSensitive(String anchorCaseSensitive) {
    this.anchorCaseSensitive = anchorCaseSensitive;
    return this;
  }

  /**
   * When set to **true**, the anchor string does not consider case when matching strings in the
   * document. The default value is **true**.
   *
   * @return anchorCaseSensitive
   */
  @Schema(
      description =
          "When set to **true**, the anchor string does not consider case when matching strings in the document. The default value is **true**.")
  public String getAnchorCaseSensitive() {
    return anchorCaseSensitive;
  }

  public void setAnchorCaseSensitive(String anchorCaseSensitive) {
    this.anchorCaseSensitive = anchorCaseSensitive;
  }

  public NotaryCertificate anchorCaseSensitiveMetadata(
      PropertyMetadata anchorCaseSensitiveMetadata) {
    this.anchorCaseSensitiveMetadata = anchorCaseSensitiveMetadata;
    return this;
  }

  /**
   * Get anchorCaseSensitiveMetadata
   *
   * @return anchorCaseSensitiveMetadata
   */
  @Schema(description = "")
  public PropertyMetadata getAnchorCaseSensitiveMetadata() {
    return anchorCaseSensitiveMetadata;
  }

  public void setAnchorCaseSensitiveMetadata(PropertyMetadata anchorCaseSensitiveMetadata) {
    this.anchorCaseSensitiveMetadata = anchorCaseSensitiveMetadata;
  }

  public NotaryCertificate anchorHorizontalAlignment(String anchorHorizontalAlignment) {
    this.anchorHorizontalAlignment = anchorHorizontalAlignment;
    return this;
  }

  /**
   * Specifies the alignment of anchor tabs with anchor strings. Possible values are **left** or
   * **right**. The default value is **left**.
   *
   * @return anchorHorizontalAlignment
   */
  @Schema(
      description =
          "Specifies the alignment of anchor tabs with anchor strings. Possible values are **left** or **right**. The default value is **left**.")
  public String getAnchorHorizontalAlignment() {
    return anchorHorizontalAlignment;
  }

  public void setAnchorHorizontalAlignment(String anchorHorizontalAlignment) {
    this.anchorHorizontalAlignment = anchorHorizontalAlignment;
  }

  public NotaryCertificate anchorHorizontalAlignmentMetadata(
      PropertyMetadata anchorHorizontalAlignmentMetadata) {
    this.anchorHorizontalAlignmentMetadata = anchorHorizontalAlignmentMetadata;
    return this;
  }

  /**
   * Get anchorHorizontalAlignmentMetadata
   *
   * @return anchorHorizontalAlignmentMetadata
   */
  @Schema(description = "")
  public PropertyMetadata getAnchorHorizontalAlignmentMetadata() {
    return anchorHorizontalAlignmentMetadata;
  }

  public void setAnchorHorizontalAlignmentMetadata(
      PropertyMetadata anchorHorizontalAlignmentMetadata) {
    this.anchorHorizontalAlignmentMetadata = anchorHorizontalAlignmentMetadata;
  }

  public NotaryCertificate anchorIgnoreIfNotPresent(String anchorIgnoreIfNotPresent) {
    this.anchorIgnoreIfNotPresent = anchorIgnoreIfNotPresent;
    return this;
  }

  /**
   * When set to **true**, this tab is ignored if anchorString is not found in the document.
   *
   * @return anchorIgnoreIfNotPresent
   */
  @Schema(
      description =
          "When set to **true**, this tab is ignored if anchorString is not found in the document.")
  public String getAnchorIgnoreIfNotPresent() {
    return anchorIgnoreIfNotPresent;
  }

  public void setAnchorIgnoreIfNotPresent(String anchorIgnoreIfNotPresent) {
    this.anchorIgnoreIfNotPresent = anchorIgnoreIfNotPresent;
  }

  public NotaryCertificate anchorIgnoreIfNotPresentMetadata(
      PropertyMetadata anchorIgnoreIfNotPresentMetadata) {
    this.anchorIgnoreIfNotPresentMetadata = anchorIgnoreIfNotPresentMetadata;
    return this;
  }

  /**
   * Get anchorIgnoreIfNotPresentMetadata
   *
   * @return anchorIgnoreIfNotPresentMetadata
   */
  @Schema(description = "")
  public PropertyMetadata getAnchorIgnoreIfNotPresentMetadata() {
    return anchorIgnoreIfNotPresentMetadata;
  }

  public void setAnchorIgnoreIfNotPresentMetadata(
      PropertyMetadata anchorIgnoreIfNotPresentMetadata) {
    this.anchorIgnoreIfNotPresentMetadata = anchorIgnoreIfNotPresentMetadata;
  }

  public NotaryCertificate anchorMatchWholeWord(String anchorMatchWholeWord) {
    this.anchorMatchWholeWord = anchorMatchWholeWord;
    return this;
  }

  /**
   * When set to **true**, the anchor string in this tab matches whole words only (strings embedded
   * in other strings are ignored.) The default value is **true**.
   *
   * @return anchorMatchWholeWord
   */
  @Schema(
      description =
          "When set to **true**, the anchor string in this tab matches whole words only (strings embedded in other strings are ignored.) The default value is **true**.")
  public String getAnchorMatchWholeWord() {
    return anchorMatchWholeWord;
  }

  public void setAnchorMatchWholeWord(String anchorMatchWholeWord) {
    this.anchorMatchWholeWord = anchorMatchWholeWord;
  }

  public NotaryCertificate anchorMatchWholeWordMetadata(
      PropertyMetadata anchorMatchWholeWordMetadata) {
    this.anchorMatchWholeWordMetadata = anchorMatchWholeWordMetadata;
    return this;
  }

  /**
   * Get anchorMatchWholeWordMetadata
   *
   * @return anchorMatchWholeWordMetadata
   */
  @Schema(description = "")
  public PropertyMetadata getAnchorMatchWholeWordMetadata() {
    return anchorMatchWholeWordMetadata;
  }

  public void setAnchorMatchWholeWordMetadata(PropertyMetadata anchorMatchWholeWordMetadata) {
    this.anchorMatchWholeWordMetadata = anchorMatchWholeWordMetadata;
  }

  public NotaryCertificate anchorString(String anchorString) {
    this.anchorString = anchorString;
    return this;
  }

  /**
   * Anchor text information for a radio button.
   *
   * @return anchorString
   */
  @Schema(description = "Anchor text information for a radio button.")
  public String getAnchorString() {
    return anchorString;
  }

  public void setAnchorString(String anchorString) {
    this.anchorString = anchorString;
  }

  public NotaryCertificate anchorStringMetadata(PropertyMetadata anchorStringMetadata) {
    this.anchorStringMetadata = anchorStringMetadata;
    return this;
  }

  /**
   * Get anchorStringMetadata
   *
   * @return anchorStringMetadata
   */
  @Schema(description = "")
  public PropertyMetadata getAnchorStringMetadata() {
    return anchorStringMetadata;
  }

  public void setAnchorStringMetadata(PropertyMetadata anchorStringMetadata) {
    this.anchorStringMetadata = anchorStringMetadata;
  }

  public NotaryCertificate anchorTabProcessorVersion(String anchorTabProcessorVersion) {
    this.anchorTabProcessorVersion = anchorTabProcessorVersion;
    return this;
  }

  /** @return anchorTabProcessorVersion */
  @Schema(description = "")
  public String getAnchorTabProcessorVersion() {
    return anchorTabProcessorVersion;
  }

  public void setAnchorTabProcessorVersion(String anchorTabProcessorVersion) {
    this.anchorTabProcessorVersion = anchorTabProcessorVersion;
  }

  public NotaryCertificate anchorTabProcessorVersionMetadata(
      PropertyMetadata anchorTabProcessorVersionMetadata) {
    this.anchorTabProcessorVersionMetadata = anchorTabProcessorVersionMetadata;
    return this;
  }

  /**
   * Get anchorTabProcessorVersionMetadata
   *
   * @return anchorTabProcessorVersionMetadata
   */
  @Schema(description = "")
  public PropertyMetadata getAnchorTabProcessorVersionMetadata() {
    return anchorTabProcessorVersionMetadata;
  }

  public void setAnchorTabProcessorVersionMetadata(
      PropertyMetadata anchorTabProcessorVersionMetadata) {
    this.anchorTabProcessorVersionMetadata = anchorTabProcessorVersionMetadata;
  }

  public NotaryCertificate anchorUnits(String anchorUnits) {
    this.anchorUnits = anchorUnits;
    return this;
  }

  /**
   * Specifies units of the X and Y offset. Units could be pixels, millimeters, centimeters, or
   * inches.
   *
   * @return anchorUnits
   */
  @Schema(
      description =
          "Specifies units of the X and Y offset. Units could be pixels, millimeters, centimeters, or inches.")
  public String getAnchorUnits() {
    return anchorUnits;
  }

  public void setAnchorUnits(String anchorUnits) {
    this.anchorUnits = anchorUnits;
  }

  public NotaryCertificate anchorUnitsMetadata(PropertyMetadata anchorUnitsMetadata) {
    this.anchorUnitsMetadata = anchorUnitsMetadata;
    return this;
  }

  /**
   * Get anchorUnitsMetadata
   *
   * @return anchorUnitsMetadata
   */
  @Schema(description = "")
  public PropertyMetadata getAnchorUnitsMetadata() {
    return anchorUnitsMetadata;
  }

  public void setAnchorUnitsMetadata(PropertyMetadata anchorUnitsMetadata) {
    this.anchorUnitsMetadata = anchorUnitsMetadata;
  }

  public NotaryCertificate anchorXOffset(String anchorXOffset) {
    this.anchorXOffset = anchorXOffset;
    return this;
  }

  /**
   * Specifies the X axis location of the tab, in anchorUnits, relative to the anchorString.
   *
   * @return anchorXOffset
   */
  @Schema(
      description =
          "Specifies the X axis location of the tab, in anchorUnits, relative to the anchorString.")
  public String getAnchorXOffset() {
    return anchorXOffset;
  }

  public void setAnchorXOffset(String anchorXOffset) {
    this.anchorXOffset = anchorXOffset;
  }

  public NotaryCertificate anchorXOffsetMetadata(PropertyMetadata anchorXOffsetMetadata) {
    this.anchorXOffsetMetadata = anchorXOffsetMetadata;
    return this;
  }

  /**
   * Get anchorXOffsetMetadata
   *
   * @return anchorXOffsetMetadata
   */
  @Schema(description = "")
  public PropertyMetadata getAnchorXOffsetMetadata() {
    return anchorXOffsetMetadata;
  }

  public void setAnchorXOffsetMetadata(PropertyMetadata anchorXOffsetMetadata) {
    this.anchorXOffsetMetadata = anchorXOffsetMetadata;
  }

  public NotaryCertificate anchorYOffset(String anchorYOffset) {
    this.anchorYOffset = anchorYOffset;
    return this;
  }

  /**
   * Specifies the Y axis location of the tab, in anchorUnits, relative to the anchorString.
   *
   * @return anchorYOffset
   */
  @Schema(
      description =
          "Specifies the Y axis location of the tab, in anchorUnits, relative to the anchorString.")
  public String getAnchorYOffset() {
    return anchorYOffset;
  }

  public void setAnchorYOffset(String anchorYOffset) {
    this.anchorYOffset = anchorYOffset;
  }

  public NotaryCertificate anchorYOffsetMetadata(PropertyMetadata anchorYOffsetMetadata) {
    this.anchorYOffsetMetadata = anchorYOffsetMetadata;
    return this;
  }

  /**
   * Get anchorYOffsetMetadata
   *
   * @return anchorYOffsetMetadata
   */
  @Schema(description = "")
  public PropertyMetadata getAnchorYOffsetMetadata() {
    return anchorYOffsetMetadata;
  }

  public void setAnchorYOffsetMetadata(PropertyMetadata anchorYOffsetMetadata) {
    this.anchorYOffsetMetadata = anchorYOffsetMetadata;
  }

  public NotaryCertificate conditionalParentLabel(String conditionalParentLabel) {
    this.conditionalParentLabel = conditionalParentLabel;
    return this;
  }

  /**
   * For conditional fields this is the TabLabel of the parent tab that controls this tab's
   * visibility.
   *
   * @return conditionalParentLabel
   */
  @Schema(
      description =
          "For conditional fields this is the TabLabel of the parent tab that controls this tab's visibility.")
  public String getConditionalParentLabel() {
    return conditionalParentLabel;
  }

  public void setConditionalParentLabel(String conditionalParentLabel) {
    this.conditionalParentLabel = conditionalParentLabel;
  }

  public NotaryCertificate conditionalParentLabelMetadata(
      PropertyMetadata conditionalParentLabelMetadata) {
    this.conditionalParentLabelMetadata = conditionalParentLabelMetadata;
    return this;
  }

  /**
   * Get conditionalParentLabelMetadata
   *
   * @return conditionalParentLabelMetadata
   */
  @Schema(description = "")
  public PropertyMetadata getConditionalParentLabelMetadata() {
    return conditionalParentLabelMetadata;
  }

  public void setConditionalParentLabelMetadata(PropertyMetadata conditionalParentLabelMetadata) {
    this.conditionalParentLabelMetadata = conditionalParentLabelMetadata;
  }

  public NotaryCertificate conditionalParentValue(String conditionalParentValue) {
    this.conditionalParentValue = conditionalParentValue;
    return this;
  }

  /**
   * For conditional fields, this is the value of the parent tab that controls the tab's visibility.
   * If the parent tab is a Checkbox, Radio button, Optional Signature, or Optional Initial use
   * \"on\" as the value to show that the parent tab is active.
   *
   * @return conditionalParentValue
   */
  @Schema(
      description =
          "For conditional fields, this is the value of the parent tab that controls the tab's visibility.  If the parent tab is a Checkbox, Radio button, Optional Signature, or Optional Initial use \"on\" as the value to show that the parent tab is active. ")
  public String getConditionalParentValue() {
    return conditionalParentValue;
  }

  public void setConditionalParentValue(String conditionalParentValue) {
    this.conditionalParentValue = conditionalParentValue;
  }

  public NotaryCertificate conditionalParentValueMetadata(
      PropertyMetadata conditionalParentValueMetadata) {
    this.conditionalParentValueMetadata = conditionalParentValueMetadata;
    return this;
  }

  /**
   * Get conditionalParentValueMetadata
   *
   * @return conditionalParentValueMetadata
   */
  @Schema(description = "")
  public PropertyMetadata getConditionalParentValueMetadata() {
    return conditionalParentValueMetadata;
  }

  public void setConditionalParentValueMetadata(PropertyMetadata conditionalParentValueMetadata) {
    this.conditionalParentValueMetadata = conditionalParentValueMetadata;
  }

  public NotaryCertificate customTabId(String customTabId) {
    this.customTabId = customTabId;
    return this;
  }

  /**
   * The DocuSign generated custom tab ID for the custom tab to be applied. This can only be used
   * when adding new tabs for a recipient. When used, the new tab inherits all the custom tab
   * properties.
   *
   * @return customTabId
   */
  @Schema(
      description =
          "The DocuSign generated custom tab ID for the custom tab to be applied. This can only be used when adding new tabs for a recipient. When used, the new tab inherits all the custom tab properties.")
  public String getCustomTabId() {
    return customTabId;
  }

  public void setCustomTabId(String customTabId) {
    this.customTabId = customTabId;
  }

  public NotaryCertificate customTabIdMetadata(PropertyMetadata customTabIdMetadata) {
    this.customTabIdMetadata = customTabIdMetadata;
    return this;
  }

  /**
   * Get customTabIdMetadata
   *
   * @return customTabIdMetadata
   */
  @Schema(description = "")
  public PropertyMetadata getCustomTabIdMetadata() {
    return customTabIdMetadata;
  }

  public void setCustomTabIdMetadata(PropertyMetadata customTabIdMetadata) {
    this.customTabIdMetadata = customTabIdMetadata;
  }

  public NotaryCertificate documentId(String documentId) {
    this.documentId = documentId;
    return this;
  }

  /**
   * Specifies the document ID number that the tab is placed on. This must refer to an existing
   * Document's ID attribute.
   *
   * @return documentId
   */
  @Schema(
      description =
          "Specifies the document ID number that the tab is placed on. This must refer to an existing Document's ID attribute.")
  public String getDocumentId() {
    return documentId;
  }

  public void setDocumentId(String documentId) {
    this.documentId = documentId;
  }

  public NotaryCertificate documentIdMetadata(PropertyMetadata documentIdMetadata) {
    this.documentIdMetadata = documentIdMetadata;
    return this;
  }

  /**
   * Get documentIdMetadata
   *
   * @return documentIdMetadata
   */
  @Schema(description = "")
  public PropertyMetadata getDocumentIdMetadata() {
    return documentIdMetadata;
  }

  public void setDocumentIdMetadata(PropertyMetadata documentIdMetadata) {
    this.documentIdMetadata = documentIdMetadata;
  }

  public NotaryCertificate errorDetails(ErrorDetails errorDetails) {
    this.errorDetails = errorDetails;
    return this;
  }

  /**
   * Get errorDetails
   *
   * @return errorDetails
   */
  @Schema(description = "")
  public ErrorDetails getErrorDetails() {
    return errorDetails;
  }

  public void setErrorDetails(ErrorDetails errorDetails) {
    this.errorDetails = errorDetails;
  }

  public NotaryCertificate formOrder(String formOrder) {
    this.formOrder = formOrder;
    return this;
  }

  /** @return formOrder */
  @Schema(description = "")
  public String getFormOrder() {
    return formOrder;
  }

  public void setFormOrder(String formOrder) {
    this.formOrder = formOrder;
  }

  public NotaryCertificate formOrderMetadata(PropertyMetadata formOrderMetadata) {
    this.formOrderMetadata = formOrderMetadata;
    return this;
  }

  /**
   * Get formOrderMetadata
   *
   * @return formOrderMetadata
   */
  @Schema(description = "")
  public PropertyMetadata getFormOrderMetadata() {
    return formOrderMetadata;
  }

  public void setFormOrderMetadata(PropertyMetadata formOrderMetadata) {
    this.formOrderMetadata = formOrderMetadata;
  }

  public NotaryCertificate formPageLabel(String formPageLabel) {
    this.formPageLabel = formPageLabel;
    return this;
  }

  /** @return formPageLabel */
  @Schema(description = "")
  public String getFormPageLabel() {
    return formPageLabel;
  }

  public void setFormPageLabel(String formPageLabel) {
    this.formPageLabel = formPageLabel;
  }

  public NotaryCertificate formPageLabelMetadata(PropertyMetadata formPageLabelMetadata) {
    this.formPageLabelMetadata = formPageLabelMetadata;
    return this;
  }

  /**
   * Get formPageLabelMetadata
   *
   * @return formPageLabelMetadata
   */
  @Schema(description = "")
  public PropertyMetadata getFormPageLabelMetadata() {
    return formPageLabelMetadata;
  }

  public void setFormPageLabelMetadata(PropertyMetadata formPageLabelMetadata) {
    this.formPageLabelMetadata = formPageLabelMetadata;
  }

  public NotaryCertificate formPageNumber(String formPageNumber) {
    this.formPageNumber = formPageNumber;
    return this;
  }

  /** @return formPageNumber */
  @Schema(description = "")
  public String getFormPageNumber() {
    return formPageNumber;
  }

  public void setFormPageNumber(String formPageNumber) {
    this.formPageNumber = formPageNumber;
  }

  public NotaryCertificate formPageNumberMetadata(PropertyMetadata formPageNumberMetadata) {
    this.formPageNumberMetadata = formPageNumberMetadata;
    return this;
  }

  /**
   * Get formPageNumberMetadata
   *
   * @return formPageNumberMetadata
   */
  @Schema(description = "")
  public PropertyMetadata getFormPageNumberMetadata() {
    return formPageNumberMetadata;
  }

  public void setFormPageNumberMetadata(PropertyMetadata formPageNumberMetadata) {
    this.formPageNumberMetadata = formPageNumberMetadata;
  }

  public NotaryCertificate height(String height) {
    this.height = height;
    return this;
  }

  /**
   * Height of the tab in pixels.
   *
   * @return height
   */
  @Schema(description = "Height of the tab in pixels.")
  public String getHeight() {
    return height;
  }

  public void setHeight(String height) {
    this.height = height;
  }

  public NotaryCertificate heightMetadata(PropertyMetadata heightMetadata) {
    this.heightMetadata = heightMetadata;
    return this;
  }

  /**
   * Get heightMetadata
   *
   * @return heightMetadata
   */
  @Schema(description = "")
  public PropertyMetadata getHeightMetadata() {
    return heightMetadata;
  }

  public void setHeightMetadata(PropertyMetadata heightMetadata) {
    this.heightMetadata = heightMetadata;
  }

  public NotaryCertificate locked(String locked) {
    this.locked = locked;
    return this;
  }

  /**
   * When set to **true**, the signer cannot change the data of the custom tab.
   *
   * @return locked
   */
  @Schema(
      description = "When set to **true**, the signer cannot change the data of the custom tab.")
  public String getLocked() {
    return locked;
  }

  public void setLocked(String locked) {
    this.locked = locked;
  }

  public NotaryCertificate lockedMetadata(PropertyMetadata lockedMetadata) {
    this.lockedMetadata = lockedMetadata;
    return this;
  }

  /**
   * Get lockedMetadata
   *
   * @return lockedMetadata
   */
  @Schema(description = "")
  public PropertyMetadata getLockedMetadata() {
    return lockedMetadata;
  }

  public void setLockedMetadata(PropertyMetadata lockedMetadata) {
    this.lockedMetadata = lockedMetadata;
  }

  public NotaryCertificate mergeField(MergeField mergeField) {
    this.mergeField = mergeField;
    return this;
  }

  /**
   * Get mergeField
   *
   * @return mergeField
   */
  @Schema(description = "")
  public MergeField getMergeField() {
    return mergeField;
  }

  public void setMergeField(MergeField mergeField) {
    this.mergeField = mergeField;
  }

  public NotaryCertificate mergeFieldXml(String mergeFieldXml) {
    this.mergeFieldXml = mergeFieldXml;
    return this;
  }

  /** @return mergeFieldXml */
  @Schema(description = "")
  public String getMergeFieldXml() {
    return mergeFieldXml;
  }

  public void setMergeFieldXml(String mergeFieldXml) {
    this.mergeFieldXml = mergeFieldXml;
  }

  public NotaryCertificate pageNumber(String pageNumber) {
    this.pageNumber = pageNumber;
    return this;
  }

  /**
   * Specifies the page number on which the tab is located.
   *
   * @return pageNumber
   */
  @Schema(description = "Specifies the page number on which the tab is located.")
  public String getPageNumber() {
    return pageNumber;
  }

  public void setPageNumber(String pageNumber) {
    this.pageNumber = pageNumber;
  }

  public NotaryCertificate pageNumberMetadata(PropertyMetadata pageNumberMetadata) {
    this.pageNumberMetadata = pageNumberMetadata;
    return this;
  }

  /**
   * Get pageNumberMetadata
   *
   * @return pageNumberMetadata
   */
  @Schema(description = "")
  public PropertyMetadata getPageNumberMetadata() {
    return pageNumberMetadata;
  }

  public void setPageNumberMetadata(PropertyMetadata pageNumberMetadata) {
    this.pageNumberMetadata = pageNumberMetadata;
  }

  public NotaryCertificate recipientId(String recipientId) {
    this.recipientId = recipientId;
    return this;
  }

  /**
   * Unique for the recipient. It is used by the tab element to indicate which recipient is to sign
   * the Document.
   *
   * @return recipientId
   */
  @Schema(
      description =
          "Unique for the recipient. It is used by the tab element to indicate which recipient is to sign the Document.")
  public String getRecipientId() {
    return recipientId;
  }

  public void setRecipientId(String recipientId) {
    this.recipientId = recipientId;
  }

  public NotaryCertificate recipientIdGuid(String recipientIdGuid) {
    this.recipientIdGuid = recipientIdGuid;
    return this;
  }

  /** @return recipientIdGuid */
  @Schema(description = "")
  public String getRecipientIdGuid() {
    return recipientIdGuid;
  }

  public void setRecipientIdGuid(String recipientIdGuid) {
    this.recipientIdGuid = recipientIdGuid;
  }

  public NotaryCertificate recipientIdGuidMetadata(PropertyMetadata recipientIdGuidMetadata) {
    this.recipientIdGuidMetadata = recipientIdGuidMetadata;
    return this;
  }

  /**
   * Get recipientIdGuidMetadata
   *
   * @return recipientIdGuidMetadata
   */
  @Schema(description = "")
  public PropertyMetadata getRecipientIdGuidMetadata() {
    return recipientIdGuidMetadata;
  }

  public void setRecipientIdGuidMetadata(PropertyMetadata recipientIdGuidMetadata) {
    this.recipientIdGuidMetadata = recipientIdGuidMetadata;
  }

  public NotaryCertificate recipientIdMetadata(PropertyMetadata recipientIdMetadata) {
    this.recipientIdMetadata = recipientIdMetadata;
    return this;
  }

  /**
   * Get recipientIdMetadata
   *
   * @return recipientIdMetadata
   */
  @Schema(description = "")
  public PropertyMetadata getRecipientIdMetadata() {
    return recipientIdMetadata;
  }

  public void setRecipientIdMetadata(PropertyMetadata recipientIdMetadata) {
    this.recipientIdMetadata = recipientIdMetadata;
  }

  public NotaryCertificate required(String required) {
    this.required = required;
    return this;
  }

  /**
   * When set to **true**, the signer is required to fill out this tab
   *
   * @return required
   */
  @Schema(description = "When set to **true**, the signer is required to fill out this tab")
  public String getRequired() {
    return required;
  }

  public void setRequired(String required) {
    this.required = required;
  }

  public NotaryCertificate requiredMetadata(PropertyMetadata requiredMetadata) {
    this.requiredMetadata = requiredMetadata;
    return this;
  }

  /**
   * Get requiredMetadata
   *
   * @return requiredMetadata
   */
  @Schema(description = "")
  public PropertyMetadata getRequiredMetadata() {
    return requiredMetadata;
  }

  public void setRequiredMetadata(PropertyMetadata requiredMetadata) {
    this.requiredMetadata = requiredMetadata;
  }

  public NotaryCertificate smartContractInformation(
      SmartContractInformation smartContractInformation) {
    this.smartContractInformation = smartContractInformation;
    return this;
  }

  /**
   * Get smartContractInformation
   *
   * @return smartContractInformation
   */
  @Schema(description = "")
  public SmartContractInformation getSmartContractInformation() {
    return smartContractInformation;
  }

  public void setSmartContractInformation(SmartContractInformation smartContractInformation) {
    this.smartContractInformation = smartContractInformation;
  }

  public NotaryCertificate status(String status) {
    this.status = status;
    return this;
  }

  /**
   * Indicates the envelope status. Valid values are: * sent - The envelope is sent to the
   * recipients. * created - The envelope is saved as a draft and can be modified and sent later.
   *
   * @return status
   */
  @Schema(
      description =
          "Indicates the envelope status. Valid values are:  * sent - The envelope is sent to the recipients.  * created - The envelope is saved as a draft and can be modified and sent later.")
  public String getStatus() {
    return status;
  }

  public void setStatus(String status) {
    this.status = status;
  }

  public NotaryCertificate statusMetadata(PropertyMetadata statusMetadata) {
    this.statusMetadata = statusMetadata;
    return this;
  }

  /**
   * Get statusMetadata
   *
   * @return statusMetadata
   */
  @Schema(description = "")
  public PropertyMetadata getStatusMetadata() {
    return statusMetadata;
  }

  public void setStatusMetadata(PropertyMetadata statusMetadata) {
    this.statusMetadata = statusMetadata;
  }

  public NotaryCertificate tabGroupLabels(java.util.List<String> tabGroupLabels) {
    this.tabGroupLabels = tabGroupLabels;
    return this;
  }

  public NotaryCertificate addTabGroupLabelsItem(String tabGroupLabelsItem) {
    if (this.tabGroupLabels == null) {
      this.tabGroupLabels = new java.util.ArrayList<String>();
    }
    this.tabGroupLabels.add(tabGroupLabelsItem);
    return this;
  }

  /** @return tabGroupLabels */
  @Schema(description = "")
  public java.util.List<String> getTabGroupLabels() {
    return tabGroupLabels;
  }

  public void setTabGroupLabels(java.util.List<String> tabGroupLabels) {
    this.tabGroupLabels = tabGroupLabels;
  }

  public NotaryCertificate tabGroupLabelsMetadata(PropertyMetadata tabGroupLabelsMetadata) {
    this.tabGroupLabelsMetadata = tabGroupLabelsMetadata;
    return this;
  }

  /**
   * Get tabGroupLabelsMetadata
   *
   * @return tabGroupLabelsMetadata
   */
  @Schema(description = "")
  public PropertyMetadata getTabGroupLabelsMetadata() {
    return tabGroupLabelsMetadata;
  }

  public void setTabGroupLabelsMetadata(PropertyMetadata tabGroupLabelsMetadata) {
    this.tabGroupLabelsMetadata = tabGroupLabelsMetadata;
  }

  public NotaryCertificate tabId(String tabId) {
    this.tabId = tabId;
    return this;
  }

  /**
   * The unique identifier for the tab. The tabid can be retrieved with the [ML:GET call].
   *
   * @return tabId
   */
  @Schema(
      description =
          "The unique identifier for the tab. The tabid can be retrieved with the [ML:GET call].     ")
  public String getTabId() {
    return tabId;
  }

  public void setTabId(String tabId) {
    this.tabId = tabId;
  }

  public NotaryCertificate tabIdMetadata(PropertyMetadata tabIdMetadata) {
    this.tabIdMetadata = tabIdMetadata;
    return this;
  }

  /**
   * Get tabIdMetadata
   *
   * @return tabIdMetadata
   */
  @Schema(description = "")
  public PropertyMetadata getTabIdMetadata() {
    return tabIdMetadata;
  }

  public void setTabIdMetadata(PropertyMetadata tabIdMetadata) {
    this.tabIdMetadata = tabIdMetadata;
  }

  public NotaryCertificate tabLabelMetadata(PropertyMetadata tabLabelMetadata) {
    this.tabLabelMetadata = tabLabelMetadata;
    return this;
  }

  /**
   * Get tabLabelMetadata
   *
   * @return tabLabelMetadata
   */
  @Schema(description = "")
  public PropertyMetadata getTabLabelMetadata() {
    return tabLabelMetadata;
  }

  public void setTabLabelMetadata(PropertyMetadata tabLabelMetadata) {
    this.tabLabelMetadata = tabLabelMetadata;
  }

  public NotaryCertificate tabOrder(String tabOrder) {
    this.tabOrder = tabOrder;
    return this;
  }

  /** @return tabOrder */
  @Schema(description = "")
  public String getTabOrder() {
    return tabOrder;
  }

  public void setTabOrder(String tabOrder) {
    this.tabOrder = tabOrder;
  }

  public NotaryCertificate tabOrderMetadata(PropertyMetadata tabOrderMetadata) {
    this.tabOrderMetadata = tabOrderMetadata;
    return this;
  }

  /**
   * Get tabOrderMetadata
   *
   * @return tabOrderMetadata
   */
  @Schema(description = "")
  public PropertyMetadata getTabOrderMetadata() {
    return tabOrderMetadata;
  }

  public void setTabOrderMetadata(PropertyMetadata tabOrderMetadata) {
    this.tabOrderMetadata = tabOrderMetadata;
  }

  public NotaryCertificate tabType(String tabType) {
    this.tabType = tabType;
    return this;
  }

  /** @return tabType */
  @Schema(description = "")
  public String getTabType() {
    return tabType;
  }

  public void setTabType(String tabType) {
    this.tabType = tabType;
  }

  public NotaryCertificate tabTypeMetadata(PropertyMetadata tabTypeMetadata) {
    this.tabTypeMetadata = tabTypeMetadata;
    return this;
  }

  /**
   * Get tabTypeMetadata
   *
   * @return tabTypeMetadata
   */
  @Schema(description = "")
  public PropertyMetadata getTabTypeMetadata() {
    return tabTypeMetadata;
  }

  public void setTabTypeMetadata(PropertyMetadata tabTypeMetadata) {
    this.tabTypeMetadata = tabTypeMetadata;
  }

  public NotaryCertificate templateLocked(String templateLocked) {
    this.templateLocked = templateLocked;
    return this;
  }

  /**
   * When set to **true**, the sender cannot change any attributes of the recipient. Used only when
   * working with template recipients.
   *
   * @return templateLocked
   */
  @Schema(
      description =
          "When set to **true**, the sender cannot change any attributes of the recipient. Used only when working with template recipients. ")
  public String getTemplateLocked() {
    return templateLocked;
  }

  public void setTemplateLocked(String templateLocked) {
    this.templateLocked = templateLocked;
  }

  public NotaryCertificate templateLockedMetadata(PropertyMetadata templateLockedMetadata) {
    this.templateLockedMetadata = templateLockedMetadata;
    return this;
  }

  /**
   * Get templateLockedMetadata
   *
   * @return templateLockedMetadata
   */
  @Schema(description = "")
  public PropertyMetadata getTemplateLockedMetadata() {
    return templateLockedMetadata;
  }

  public void setTemplateLockedMetadata(PropertyMetadata templateLockedMetadata) {
    this.templateLockedMetadata = templateLockedMetadata;
  }

  public NotaryCertificate templateRequired(String templateRequired) {
    this.templateRequired = templateRequired;
    return this;
  }

  /**
   * When set to **true**, the sender may not remove the recipient. Used only when working with
   * template recipients.
   *
   * @return templateRequired
   */
  @Schema(
      description =
          "When set to **true**, the sender may not remove the recipient. Used only when working with template recipients.")
  public String getTemplateRequired() {
    return templateRequired;
  }

  public void setTemplateRequired(String templateRequired) {
    this.templateRequired = templateRequired;
  }

  public NotaryCertificate templateRequiredMetadata(PropertyMetadata templateRequiredMetadata) {
    this.templateRequiredMetadata = templateRequiredMetadata;
    return this;
  }

  /**
   * Get templateRequiredMetadata
   *
   * @return templateRequiredMetadata
   */
  @Schema(description = "")
  public PropertyMetadata getTemplateRequiredMetadata() {
    return templateRequiredMetadata;
  }

  public void setTemplateRequiredMetadata(PropertyMetadata templateRequiredMetadata) {
    this.templateRequiredMetadata = templateRequiredMetadata;
  }

  public NotaryCertificate tooltip(String tooltip) {
    this.tooltip = tooltip;
    return this;
  }

  /** @return tooltip */
  @Schema(description = "")
  public String getTooltip() {
    return tooltip;
  }

  public void setTooltip(String tooltip) {
    this.tooltip = tooltip;
  }

  public NotaryCertificate toolTipMetadata(PropertyMetadata toolTipMetadata) {
    this.toolTipMetadata = toolTipMetadata;
    return this;
  }

  /**
   * Get toolTipMetadata
   *
   * @return toolTipMetadata
   */
  @Schema(description = "")
  public PropertyMetadata getToolTipMetadata() {
    return toolTipMetadata;
  }

  public void setToolTipMetadata(PropertyMetadata toolTipMetadata) {
    this.toolTipMetadata = toolTipMetadata;
  }

  public NotaryCertificate width(String width) {
    this.width = width;
    return this;
  }

  /**
   * Width of the tab in pixels.
   *
   * @return width
   */
  @Schema(description = "Width of the tab in pixels.")
  public String getWidth() {
    return width;
  }

  public void setWidth(String width) {
    this.width = width;
  }

  public NotaryCertificate widthMetadata(PropertyMetadata widthMetadata) {
    this.widthMetadata = widthMetadata;
    return this;
  }

  /**
   * Get widthMetadata
   *
   * @return widthMetadata
   */
  @Schema(description = "")
  public PropertyMetadata getWidthMetadata() {
    return widthMetadata;
  }

  public void setWidthMetadata(PropertyMetadata widthMetadata) {
    this.widthMetadata = widthMetadata;
  }

  public NotaryCertificate xPosition(String xPosition) {
    this.xPosition = xPosition;
    return this;
  }

  /**
   * This indicates the horizontal offset of the object on the page. DocuSign uses 72 DPI when
   * determining position.
   *
   * @return xPosition
   */
  @Schema(
      description =
          "This indicates the horizontal offset of the object on the page. DocuSign uses 72 DPI when determining position.")
  public String getXPosition() {
    return xPosition;
  }

  public void setXPosition(String xPosition) {
    this.xPosition = xPosition;
  }

  public NotaryCertificate xPositionMetadata(PropertyMetadata xPositionMetadata) {
    this.xPositionMetadata = xPositionMetadata;
    return this;
  }

  /**
   * Get xPositionMetadata
   *
   * @return xPositionMetadata
   */
  @Schema(description = "")
  public PropertyMetadata getXPositionMetadata() {
    return xPositionMetadata;
  }

  public void setXPositionMetadata(PropertyMetadata xPositionMetadata) {
    this.xPositionMetadata = xPositionMetadata;
  }

  public NotaryCertificate yPosition(String yPosition) {
    this.yPosition = yPosition;
    return this;
  }

  /**
   * This indicates the vertical offset of the object on the page. DocuSign uses 72 DPI when
   * determining position.
   *
   * @return yPosition
   */
  @Schema(
      description =
          "This indicates the vertical offset of the object on the page. DocuSign uses 72 DPI when determining position.")
  public String getYPosition() {
    return yPosition;
  }

  public void setYPosition(String yPosition) {
    this.yPosition = yPosition;
  }

  public NotaryCertificate yPositionMetadata(PropertyMetadata yPositionMetadata) {
    this.yPositionMetadata = yPositionMetadata;
    return this;
  }

  /**
   * Get yPositionMetadata
   *
   * @return yPositionMetadata
   */
  @Schema(description = "")
  public PropertyMetadata getYPositionMetadata() {
    return yPositionMetadata;
  }

  public void setYPositionMetadata(PropertyMetadata yPositionMetadata) {
    this.yPositionMetadata = yPositionMetadata;
  }

  @Override
  public boolean equals(java.lang.Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    NotaryCertificate notaryCertificate = (NotaryCertificate) o;
    return Objects.equals(
            this.anchorAllowWhiteSpaceInCharacters,
            notaryCertificate.anchorAllowWhiteSpaceInCharacters)
        && Objects.equals(
            this.anchorAllowWhiteSpaceInCharactersMetadata,
            notaryCertificate.anchorAllowWhiteSpaceInCharactersMetadata)
        && Objects.equals(this.anchorCaseSensitive, notaryCertificate.anchorCaseSensitive)
        && Objects.equals(
            this.anchorCaseSensitiveMetadata, notaryCertificate.anchorCaseSensitiveMetadata)
        && Objects.equals(
            this.anchorHorizontalAlignment, notaryCertificate.anchorHorizontalAlignment)
        && Objects.equals(
            this.anchorHorizontalAlignmentMetadata,
            notaryCertificate.anchorHorizontalAlignmentMetadata)
        && Objects.equals(this.anchorIgnoreIfNotPresent, notaryCertificate.anchorIgnoreIfNotPresent)
        && Objects.equals(
            this.anchorIgnoreIfNotPresentMetadata,
            notaryCertificate.anchorIgnoreIfNotPresentMetadata)
        && Objects.equals(this.anchorMatchWholeWord, notaryCertificate.anchorMatchWholeWord)
        && Objects.equals(
            this.anchorMatchWholeWordMetadata, notaryCertificate.anchorMatchWholeWordMetadata)
        && Objects.equals(this.anchorString, notaryCertificate.anchorString)
        && Objects.equals(this.anchorStringMetadata, notaryCertificate.anchorStringMetadata)
        && Objects.equals(
            this.anchorTabProcessorVersion, notaryCertificate.anchorTabProcessorVersion)
        && Objects.equals(
            this.anchorTabProcessorVersionMetadata,
            notaryCertificate.anchorTabProcessorVersionMetadata)
        && Objects.equals(this.anchorUnits, notaryCertificate.anchorUnits)
        && Objects.equals(this.anchorUnitsMetadata, notaryCertificate.anchorUnitsMetadata)
        && Objects.equals(this.anchorXOffset, notaryCertificate.anchorXOffset)
        && Objects.equals(this.anchorXOffsetMetadata, notaryCertificate.anchorXOffsetMetadata)
        && Objects.equals(this.anchorYOffset, notaryCertificate.anchorYOffset)
        && Objects.equals(this.anchorYOffsetMetadata, notaryCertificate.anchorYOffsetMetadata)
        && Objects.equals(this.conditionalParentLabel, notaryCertificate.conditionalParentLabel)
        && Objects.equals(
            this.conditionalParentLabelMetadata, notaryCertificate.conditionalParentLabelMetadata)
        && Objects.equals(this.conditionalParentValue, notaryCertificate.conditionalParentValue)
        && Objects.equals(
            this.conditionalParentValueMetadata, notaryCertificate.conditionalParentValueMetadata)
        && Objects.equals(this.customTabId, notaryCertificate.customTabId)
        && Objects.equals(this.customTabIdMetadata, notaryCertificate.customTabIdMetadata)
        && Objects.equals(this.documentId, notaryCertificate.documentId)
        && Objects.equals(this.documentIdMetadata, notaryCertificate.documentIdMetadata)
        && Objects.equals(this.errorDetails, notaryCertificate.errorDetails)
        && Objects.equals(this.formOrder, notaryCertificate.formOrder)
        && Objects.equals(this.formOrderMetadata, notaryCertificate.formOrderMetadata)
        && Objects.equals(this.formPageLabel, notaryCertificate.formPageLabel)
        && Objects.equals(this.formPageLabelMetadata, notaryCertificate.formPageLabelMetadata)
        && Objects.equals(this.formPageNumber, notaryCertificate.formPageNumber)
        && Objects.equals(this.formPageNumberMetadata, notaryCertificate.formPageNumberMetadata)
        && Objects.equals(this.height, notaryCertificate.height)
        && Objects.equals(this.heightMetadata, notaryCertificate.heightMetadata)
        && Objects.equals(this.locked, notaryCertificate.locked)
        && Objects.equals(this.lockedMetadata, notaryCertificate.lockedMetadata)
        && Objects.equals(this.mergeField, notaryCertificate.mergeField)
        && Objects.equals(this.mergeFieldXml, notaryCertificate.mergeFieldXml)
        && Objects.equals(this.pageNumber, notaryCertificate.pageNumber)
        && Objects.equals(this.pageNumberMetadata, notaryCertificate.pageNumberMetadata)
        && Objects.equals(this.recipientId, notaryCertificate.recipientId)
        && Objects.equals(this.recipientIdGuid, notaryCertificate.recipientIdGuid)
        && Objects.equals(this.recipientIdGuidMetadata, notaryCertificate.recipientIdGuidMetadata)
        && Objects.equals(this.recipientIdMetadata, notaryCertificate.recipientIdMetadata)
        && Objects.equals(this.required, notaryCertificate.required)
        && Objects.equals(this.requiredMetadata, notaryCertificate.requiredMetadata)
        && Objects.equals(this.smartContractInformation, notaryCertificate.smartContractInformation)
        && Objects.equals(this.status, notaryCertificate.status)
        && Objects.equals(this.statusMetadata, notaryCertificate.statusMetadata)
        && Objects.equals(this.tabGroupLabels, notaryCertificate.tabGroupLabels)
        && Objects.equals(this.tabGroupLabelsMetadata, notaryCertificate.tabGroupLabelsMetadata)
        && Objects.equals(this.tabId, notaryCertificate.tabId)
        && Objects.equals(this.tabIdMetadata, notaryCertificate.tabIdMetadata)
        && Objects.equals(this.tabLabelMetadata, notaryCertificate.tabLabelMetadata)
        && Objects.equals(this.tabOrder, notaryCertificate.tabOrder)
        && Objects.equals(this.tabOrderMetadata, notaryCertificate.tabOrderMetadata)
        && Objects.equals(this.tabType, notaryCertificate.tabType)
        && Objects.equals(this.tabTypeMetadata, notaryCertificate.tabTypeMetadata)
        && Objects.equals(this.templateLocked, notaryCertificate.templateLocked)
        && Objects.equals(this.templateLockedMetadata, notaryCertificate.templateLockedMetadata)
        && Objects.equals(this.templateRequired, notaryCertificate.templateRequired)
        && Objects.equals(this.templateRequiredMetadata, notaryCertificate.templateRequiredMetadata)
        && Objects.equals(this.tooltip, notaryCertificate.tooltip)
        && Objects.equals(this.toolTipMetadata, notaryCertificate.toolTipMetadata)
        && Objects.equals(this.width, notaryCertificate.width)
        && Objects.equals(this.widthMetadata, notaryCertificate.widthMetadata)
        && Objects.equals(this.xPosition, notaryCertificate.xPosition)
        && Objects.equals(this.xPositionMetadata, notaryCertificate.xPositionMetadata)
        && Objects.equals(this.yPosition, notaryCertificate.yPosition)
        && Objects.equals(this.yPositionMetadata, notaryCertificate.yPositionMetadata);
  }

  @Override
  public int hashCode() {
    return Objects.hash(
        anchorAllowWhiteSpaceInCharacters,
        anchorAllowWhiteSpaceInCharactersMetadata,
        anchorCaseSensitive,
        anchorCaseSensitiveMetadata,
        anchorHorizontalAlignment,
        anchorHorizontalAlignmentMetadata,
        anchorIgnoreIfNotPresent,
        anchorIgnoreIfNotPresentMetadata,
        anchorMatchWholeWord,
        anchorMatchWholeWordMetadata,
        anchorString,
        anchorStringMetadata,
        anchorTabProcessorVersion,
        anchorTabProcessorVersionMetadata,
        anchorUnits,
        anchorUnitsMetadata,
        anchorXOffset,
        anchorXOffsetMetadata,
        anchorYOffset,
        anchorYOffsetMetadata,
        conditionalParentLabel,
        conditionalParentLabelMetadata,
        conditionalParentValue,
        conditionalParentValueMetadata,
        customTabId,
        customTabIdMetadata,
        documentId,
        documentIdMetadata,
        errorDetails,
        formOrder,
        formOrderMetadata,
        formPageLabel,
        formPageLabelMetadata,
        formPageNumber,
        formPageNumberMetadata,
        height,
        heightMetadata,
        locked,
        lockedMetadata,
        mergeField,
        mergeFieldXml,
        pageNumber,
        pageNumberMetadata,
        recipientId,
        recipientIdGuid,
        recipientIdGuidMetadata,
        recipientIdMetadata,
        required,
        requiredMetadata,
        smartContractInformation,
        status,
        statusMetadata,
        tabGroupLabels,
        tabGroupLabelsMetadata,
        tabId,
        tabIdMetadata,
        tabLabelMetadata,
        tabOrder,
        tabOrderMetadata,
        tabType,
        tabTypeMetadata,
        templateLocked,
        templateLockedMetadata,
        templateRequired,
        templateRequiredMetadata,
        tooltip,
        toolTipMetadata,
        width,
        widthMetadata,
        xPosition,
        xPositionMetadata,
        yPosition,
        yPositionMetadata);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class NotaryCertificate {\n");

    sb.append("    anchorAllowWhiteSpaceInCharacters: ")
        .append(toIndentedString(anchorAllowWhiteSpaceInCharacters))
        .append("\n");
    sb.append("    anchorAllowWhiteSpaceInCharactersMetadata: ")
        .append(toIndentedString(anchorAllowWhiteSpaceInCharactersMetadata))
        .append("\n");
    sb.append("    anchorCaseSensitive: ")
        .append(toIndentedString(anchorCaseSensitive))
        .append("\n");
    sb.append("    anchorCaseSensitiveMetadata: ")
        .append(toIndentedString(anchorCaseSensitiveMetadata))
        .append("\n");
    sb.append("    anchorHorizontalAlignment: ")
        .append(toIndentedString(anchorHorizontalAlignment))
        .append("\n");
    sb.append("    anchorHorizontalAlignmentMetadata: ")
        .append(toIndentedString(anchorHorizontalAlignmentMetadata))
        .append("\n");
    sb.append("    anchorIgnoreIfNotPresent: ")
        .append(toIndentedString(anchorIgnoreIfNotPresent))
        .append("\n");
    sb.append("    anchorIgnoreIfNotPresentMetadata: ")
        .append(toIndentedString(anchorIgnoreIfNotPresentMetadata))
        .append("\n");
    sb.append("    anchorMatchWholeWord: ")
        .append(toIndentedString(anchorMatchWholeWord))
        .append("\n");
    sb.append("    anchorMatchWholeWordMetadata: ")
        .append(toIndentedString(anchorMatchWholeWordMetadata))
        .append("\n");
    sb.append("    anchorString: ").append(toIndentedString(anchorString)).append("\n");
    sb.append("    anchorStringMetadata: ")
        .append(toIndentedString(anchorStringMetadata))
        .append("\n");
    sb.append("    anchorTabProcessorVersion: ")
        .append(toIndentedString(anchorTabProcessorVersion))
        .append("\n");
    sb.append("    anchorTabProcessorVersionMetadata: ")
        .append(toIndentedString(anchorTabProcessorVersionMetadata))
        .append("\n");
    sb.append("    anchorUnits: ").append(toIndentedString(anchorUnits)).append("\n");
    sb.append("    anchorUnitsMetadata: ")
        .append(toIndentedString(anchorUnitsMetadata))
        .append("\n");
    sb.append("    anchorXOffset: ").append(toIndentedString(anchorXOffset)).append("\n");
    sb.append("    anchorXOffsetMetadata: ")
        .append(toIndentedString(anchorXOffsetMetadata))
        .append("\n");
    sb.append("    anchorYOffset: ").append(toIndentedString(anchorYOffset)).append("\n");
    sb.append("    anchorYOffsetMetadata: ")
        .append(toIndentedString(anchorYOffsetMetadata))
        .append("\n");
    sb.append("    conditionalParentLabel: ")
        .append(toIndentedString(conditionalParentLabel))
        .append("\n");
    sb.append("    conditionalParentLabelMetadata: ")
        .append(toIndentedString(conditionalParentLabelMetadata))
        .append("\n");
    sb.append("    conditionalParentValue: ")
        .append(toIndentedString(conditionalParentValue))
        .append("\n");
    sb.append("    conditionalParentValueMetadata: ")
        .append(toIndentedString(conditionalParentValueMetadata))
        .append("\n");
    sb.append("    customTabId: ").append(toIndentedString(customTabId)).append("\n");
    sb.append("    customTabIdMetadata: ")
        .append(toIndentedString(customTabIdMetadata))
        .append("\n");
    sb.append("    documentId: ").append(toIndentedString(documentId)).append("\n");
    sb.append("    documentIdMetadata: ").append(toIndentedString(documentIdMetadata)).append("\n");
    sb.append("    errorDetails: ").append(toIndentedString(errorDetails)).append("\n");
    sb.append("    formOrder: ").append(toIndentedString(formOrder)).append("\n");
    sb.append("    formOrderMetadata: ").append(toIndentedString(formOrderMetadata)).append("\n");
    sb.append("    formPageLabel: ").append(toIndentedString(formPageLabel)).append("\n");
    sb.append("    formPageLabelMetadata: ")
        .append(toIndentedString(formPageLabelMetadata))
        .append("\n");
    sb.append("    formPageNumber: ").append(toIndentedString(formPageNumber)).append("\n");
    sb.append("    formPageNumberMetadata: ")
        .append(toIndentedString(formPageNumberMetadata))
        .append("\n");
    sb.append("    height: ").append(toIndentedString(height)).append("\n");
    sb.append("    heightMetadata: ").append(toIndentedString(heightMetadata)).append("\n");
    sb.append("    locked: ").append(toIndentedString(locked)).append("\n");
    sb.append("    lockedMetadata: ").append(toIndentedString(lockedMetadata)).append("\n");
    sb.append("    mergeField: ").append(toIndentedString(mergeField)).append("\n");
    sb.append("    mergeFieldXml: ").append(toIndentedString(mergeFieldXml)).append("\n");
    sb.append("    pageNumber: ").append(toIndentedString(pageNumber)).append("\n");
    sb.append("    pageNumberMetadata: ").append(toIndentedString(pageNumberMetadata)).append("\n");
    sb.append("    recipientId: ").append(toIndentedString(recipientId)).append("\n");
    sb.append("    recipientIdGuid: ").append(toIndentedString(recipientIdGuid)).append("\n");
    sb.append("    recipientIdGuidMetadata: ")
        .append(toIndentedString(recipientIdGuidMetadata))
        .append("\n");
    sb.append("    recipientIdMetadata: ")
        .append(toIndentedString(recipientIdMetadata))
        .append("\n");
    sb.append("    required: ").append(toIndentedString(required)).append("\n");
    sb.append("    requiredMetadata: ").append(toIndentedString(requiredMetadata)).append("\n");
    sb.append("    smartContractInformation: ")
        .append(toIndentedString(smartContractInformation))
        .append("\n");
    sb.append("    status: ").append(toIndentedString(status)).append("\n");
    sb.append("    statusMetadata: ").append(toIndentedString(statusMetadata)).append("\n");
    sb.append("    tabGroupLabels: ").append(toIndentedString(tabGroupLabels)).append("\n");
    sb.append("    tabGroupLabelsMetadata: ")
        .append(toIndentedString(tabGroupLabelsMetadata))
        .append("\n");
    sb.append("    tabId: ").append(toIndentedString(tabId)).append("\n");
    sb.append("    tabIdMetadata: ").append(toIndentedString(tabIdMetadata)).append("\n");
    sb.append("    tabLabelMetadata: ").append(toIndentedString(tabLabelMetadata)).append("\n");
    sb.append("    tabOrder: ").append(toIndentedString(tabOrder)).append("\n");
    sb.append("    tabOrderMetadata: ").append(toIndentedString(tabOrderMetadata)).append("\n");
    sb.append("    tabType: ").append(toIndentedString(tabType)).append("\n");
    sb.append("    tabTypeMetadata: ").append(toIndentedString(tabTypeMetadata)).append("\n");
    sb.append("    templateLocked: ").append(toIndentedString(templateLocked)).append("\n");
    sb.append("    templateLockedMetadata: ")
        .append(toIndentedString(templateLockedMetadata))
        .append("\n");
    sb.append("    templateRequired: ").append(toIndentedString(templateRequired)).append("\n");
    sb.append("    templateRequiredMetadata: ")
        .append(toIndentedString(templateRequiredMetadata))
        .append("\n");
    sb.append("    tooltip: ").append(toIndentedString(tooltip)).append("\n");
    sb.append("    toolTipMetadata: ").append(toIndentedString(toolTipMetadata)).append("\n");
    sb.append("    width: ").append(toIndentedString(width)).append("\n");
    sb.append("    widthMetadata: ").append(toIndentedString(widthMetadata)).append("\n");
    sb.append("    xPosition: ").append(toIndentedString(xPosition)).append("\n");
    sb.append("    xPositionMetadata: ").append(toIndentedString(xPositionMetadata)).append("\n");
    sb.append("    yPosition: ").append(toIndentedString(yPosition)).append("\n");
    sb.append("    yPositionMetadata: ").append(toIndentedString(yPositionMetadata)).append("\n");
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
