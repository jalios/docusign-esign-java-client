package com.docusign.esign.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.annotations.ApiModelProperty;
import java.util.Objects;

/** Date. */
public class Date {
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

  @JsonProperty("bold")
  private String bold = null;

  @JsonProperty("boldMetadata")
  private PropertyMetadata boldMetadata = null;

  @JsonProperty("caption")
  private String caption = null;

  @JsonProperty("captionMetadata")
  private PropertyMetadata captionMetadata = null;

  @JsonProperty("concealValueOnDocument")
  private String concealValueOnDocument = null;

  @JsonProperty("concealValueOnDocumentMetadata")
  private PropertyMetadata concealValueOnDocumentMetadata = null;

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

  @JsonProperty("disableAutoSize")
  private String disableAutoSize = null;

  @JsonProperty("disableAutoSizeMetadata")
  private PropertyMetadata disableAutoSizeMetadata = null;

  @JsonProperty("documentId")
  private String documentId = null;

  @JsonProperty("documentIdMetadata")
  private PropertyMetadata documentIdMetadata = null;

  @JsonProperty("errorDetails")
  private ErrorDetails errorDetails = null;

  @JsonProperty("font")
  private String font = null;

  @JsonProperty("fontColor")
  private String fontColor = null;

  @JsonProperty("fontColorMetadata")
  private PropertyMetadata fontColorMetadata = null;

  @JsonProperty("fontMetadata")
  private PropertyMetadata fontMetadata = null;

  @JsonProperty("fontSize")
  private String fontSize = null;

  @JsonProperty("fontSizeMetadata")
  private PropertyMetadata fontSizeMetadata = null;

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

  @JsonProperty("italic")
  private String italic = null;

  @JsonProperty("italicMetadata")
  private PropertyMetadata italicMetadata = null;

  @JsonProperty("localePolicy")
  private LocalePolicyTab localePolicy = null;

  @JsonProperty("locked")
  private String locked = null;

  @JsonProperty("lockedMetadata")
  private PropertyMetadata lockedMetadata = null;

  @JsonProperty("maxLength")
  private String maxLength = null;

  @JsonProperty("maxLengthMetadata")
  private PropertyMetadata maxLengthMetadata = null;

  @JsonProperty("mergeField")
  private MergeField mergeField = null;

  @JsonProperty("mergeFieldXml")
  private String mergeFieldXml = null;

  @JsonProperty("name")
  private String name = null;

  @JsonProperty("nameMetadata")
  private PropertyMetadata nameMetadata = null;

  @JsonProperty("originalValue")
  private String originalValue = null;

  @JsonProperty("originalValueMetadata")
  private PropertyMetadata originalValueMetadata = null;

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

  @JsonProperty("requireAll")
  private String requireAll = null;

  @JsonProperty("requireAllMetadata")
  private PropertyMetadata requireAllMetadata = null;

  @JsonProperty("required")
  private String required = null;

  @JsonProperty("requiredMetadata")
  private PropertyMetadata requiredMetadata = null;

  @JsonProperty("requireInitialOnSharedChange")
  private String requireInitialOnSharedChange = null;

  @JsonProperty("requireInitialOnSharedChangeMetadata")
  private PropertyMetadata requireInitialOnSharedChangeMetadata = null;

  @JsonProperty("senderRequired")
  private String senderRequired = null;

  @JsonProperty("senderRequiredMetadata")
  private PropertyMetadata senderRequiredMetadata = null;

  @JsonProperty("shared")
  private String shared = null;

  @JsonProperty("sharedMetadata")
  private PropertyMetadata sharedMetadata = null;

  @JsonProperty("shareToRecipients")
  private String shareToRecipients = null;

  @JsonProperty("shareToRecipientsMetadata")
  private PropertyMetadata shareToRecipientsMetadata = null;

  @JsonProperty("smartContractInformation")
  private SmartContractInformation smartContractInformation = null;

  @JsonProperty("source")
  private String source = null;

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

  @JsonProperty("tabLabel")
  private String tabLabel = null;

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

  @JsonProperty("underline")
  private String underline = null;

  @JsonProperty("underlineMetadata")
  private PropertyMetadata underlineMetadata = null;

  @JsonProperty("validationMessage")
  private String validationMessage = null;

  @JsonProperty("validationMessageMetadata")
  private PropertyMetadata validationMessageMetadata = null;

  @JsonProperty("validationPattern")
  private String validationPattern = null;

  @JsonProperty("validationPatternMetadata")
  private PropertyMetadata validationPatternMetadata = null;

  @JsonProperty("value")
  private String value = null;

  @JsonProperty("valueMetadata")
  private PropertyMetadata valueMetadata = null;

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

  /**
   * anchorAllowWhiteSpaceInCharacters.
   *
   * @return Date
   */
  public Date anchorAllowWhiteSpaceInCharacters(String anchorAllowWhiteSpaceInCharacters) {
    this.anchorAllowWhiteSpaceInCharacters = anchorAllowWhiteSpaceInCharacters;
    return this;
  }

  /**
   * .
   *
   * @return anchorAllowWhiteSpaceInCharacters
   */
  @ApiModelProperty(value = "")
  public String getAnchorAllowWhiteSpaceInCharacters() {
    return anchorAllowWhiteSpaceInCharacters;
  }

  /** setAnchorAllowWhiteSpaceInCharacters. */
  public void setAnchorAllowWhiteSpaceInCharacters(String anchorAllowWhiteSpaceInCharacters) {
    this.anchorAllowWhiteSpaceInCharacters = anchorAllowWhiteSpaceInCharacters;
  }

  /**
   * anchorAllowWhiteSpaceInCharactersMetadata.
   *
   * @return Date
   */
  public Date anchorAllowWhiteSpaceInCharactersMetadata(
      PropertyMetadata anchorAllowWhiteSpaceInCharactersMetadata) {
    this.anchorAllowWhiteSpaceInCharactersMetadata = anchorAllowWhiteSpaceInCharactersMetadata;
    return this;
  }

  /**
   * Get anchorAllowWhiteSpaceInCharactersMetadata.
   *
   * @return anchorAllowWhiteSpaceInCharactersMetadata
   */
  @ApiModelProperty(value = "")
  public PropertyMetadata getAnchorAllowWhiteSpaceInCharactersMetadata() {
    return anchorAllowWhiteSpaceInCharactersMetadata;
  }

  /** setAnchorAllowWhiteSpaceInCharactersMetadata. */
  public void setAnchorAllowWhiteSpaceInCharactersMetadata(
      PropertyMetadata anchorAllowWhiteSpaceInCharactersMetadata) {
    this.anchorAllowWhiteSpaceInCharactersMetadata = anchorAllowWhiteSpaceInCharactersMetadata;
  }

  /**
   * anchorCaseSensitive.
   *
   * @return Date
   */
  public Date anchorCaseSensitive(String anchorCaseSensitive) {
    this.anchorCaseSensitive = anchorCaseSensitive;
    return this;
  }

  /**
   * When set to **true**, the anchor string does not consider case when matching strings in the
   * document. The default value is **true**..
   *
   * @return anchorCaseSensitive
   */
  @ApiModelProperty(
      value =
          "When set to **true**, the anchor string does not consider case when matching strings in the document. The default value is **true**.")
  public String getAnchorCaseSensitive() {
    return anchorCaseSensitive;
  }

  /** setAnchorCaseSensitive. */
  public void setAnchorCaseSensitive(String anchorCaseSensitive) {
    this.anchorCaseSensitive = anchorCaseSensitive;
  }

  /**
   * anchorCaseSensitiveMetadata.
   *
   * @return Date
   */
  public Date anchorCaseSensitiveMetadata(PropertyMetadata anchorCaseSensitiveMetadata) {
    this.anchorCaseSensitiveMetadata = anchorCaseSensitiveMetadata;
    return this;
  }

  /**
   * Get anchorCaseSensitiveMetadata.
   *
   * @return anchorCaseSensitiveMetadata
   */
  @ApiModelProperty(value = "")
  public PropertyMetadata getAnchorCaseSensitiveMetadata() {
    return anchorCaseSensitiveMetadata;
  }

  /** setAnchorCaseSensitiveMetadata. */
  public void setAnchorCaseSensitiveMetadata(PropertyMetadata anchorCaseSensitiveMetadata) {
    this.anchorCaseSensitiveMetadata = anchorCaseSensitiveMetadata;
  }

  /**
   * anchorHorizontalAlignment.
   *
   * @return Date
   */
  public Date anchorHorizontalAlignment(String anchorHorizontalAlignment) {
    this.anchorHorizontalAlignment = anchorHorizontalAlignment;
    return this;
  }

  /**
   * Specifies the alignment of anchor tabs with anchor strings. Possible values are **left** or
   * **right**. The default value is **left**..
   *
   * @return anchorHorizontalAlignment
   */
  @ApiModelProperty(
      value =
          "Specifies the alignment of anchor tabs with anchor strings. Possible values are **left** or **right**. The default value is **left**.")
  public String getAnchorHorizontalAlignment() {
    return anchorHorizontalAlignment;
  }

  /** setAnchorHorizontalAlignment. */
  public void setAnchorHorizontalAlignment(String anchorHorizontalAlignment) {
    this.anchorHorizontalAlignment = anchorHorizontalAlignment;
  }

  /**
   * anchorHorizontalAlignmentMetadata.
   *
   * @return Date
   */
  public Date anchorHorizontalAlignmentMetadata(
      PropertyMetadata anchorHorizontalAlignmentMetadata) {
    this.anchorHorizontalAlignmentMetadata = anchorHorizontalAlignmentMetadata;
    return this;
  }

  /**
   * Get anchorHorizontalAlignmentMetadata.
   *
   * @return anchorHorizontalAlignmentMetadata
   */
  @ApiModelProperty(value = "")
  public PropertyMetadata getAnchorHorizontalAlignmentMetadata() {
    return anchorHorizontalAlignmentMetadata;
  }

  /** setAnchorHorizontalAlignmentMetadata. */
  public void setAnchorHorizontalAlignmentMetadata(
      PropertyMetadata anchorHorizontalAlignmentMetadata) {
    this.anchorHorizontalAlignmentMetadata = anchorHorizontalAlignmentMetadata;
  }

  /**
   * anchorIgnoreIfNotPresent.
   *
   * @return Date
   */
  public Date anchorIgnoreIfNotPresent(String anchorIgnoreIfNotPresent) {
    this.anchorIgnoreIfNotPresent = anchorIgnoreIfNotPresent;
    return this;
  }

  /**
   * When set to **true**, this tab is ignored if anchorString is not found in the document..
   *
   * @return anchorIgnoreIfNotPresent
   */
  @ApiModelProperty(
      value =
          "When set to **true**, this tab is ignored if anchorString is not found in the document.")
  public String getAnchorIgnoreIfNotPresent() {
    return anchorIgnoreIfNotPresent;
  }

  /** setAnchorIgnoreIfNotPresent. */
  public void setAnchorIgnoreIfNotPresent(String anchorIgnoreIfNotPresent) {
    this.anchorIgnoreIfNotPresent = anchorIgnoreIfNotPresent;
  }

  /**
   * anchorIgnoreIfNotPresentMetadata.
   *
   * @return Date
   */
  public Date anchorIgnoreIfNotPresentMetadata(PropertyMetadata anchorIgnoreIfNotPresentMetadata) {
    this.anchorIgnoreIfNotPresentMetadata = anchorIgnoreIfNotPresentMetadata;
    return this;
  }

  /**
   * Get anchorIgnoreIfNotPresentMetadata.
   *
   * @return anchorIgnoreIfNotPresentMetadata
   */
  @ApiModelProperty(value = "")
  public PropertyMetadata getAnchorIgnoreIfNotPresentMetadata() {
    return anchorIgnoreIfNotPresentMetadata;
  }

  /** setAnchorIgnoreIfNotPresentMetadata. */
  public void setAnchorIgnoreIfNotPresentMetadata(
      PropertyMetadata anchorIgnoreIfNotPresentMetadata) {
    this.anchorIgnoreIfNotPresentMetadata = anchorIgnoreIfNotPresentMetadata;
  }

  /**
   * anchorMatchWholeWord.
   *
   * @return Date
   */
  public Date anchorMatchWholeWord(String anchorMatchWholeWord) {
    this.anchorMatchWholeWord = anchorMatchWholeWord;
    return this;
  }

  /**
   * When set to **true**, the anchor string in this tab matches whole words only (strings embedded
   * in other strings are ignored.) The default value is **true**..
   *
   * @return anchorMatchWholeWord
   */
  @ApiModelProperty(
      value =
          "When set to **true**, the anchor string in this tab matches whole words only (strings embedded in other strings are ignored.) The default value is **true**.")
  public String getAnchorMatchWholeWord() {
    return anchorMatchWholeWord;
  }

  /** setAnchorMatchWholeWord. */
  public void setAnchorMatchWholeWord(String anchorMatchWholeWord) {
    this.anchorMatchWholeWord = anchorMatchWholeWord;
  }

  /**
   * anchorMatchWholeWordMetadata.
   *
   * @return Date
   */
  public Date anchorMatchWholeWordMetadata(PropertyMetadata anchorMatchWholeWordMetadata) {
    this.anchorMatchWholeWordMetadata = anchorMatchWholeWordMetadata;
    return this;
  }

  /**
   * Get anchorMatchWholeWordMetadata.
   *
   * @return anchorMatchWholeWordMetadata
   */
  @ApiModelProperty(value = "")
  public PropertyMetadata getAnchorMatchWholeWordMetadata() {
    return anchorMatchWholeWordMetadata;
  }

  /** setAnchorMatchWholeWordMetadata. */
  public void setAnchorMatchWholeWordMetadata(PropertyMetadata anchorMatchWholeWordMetadata) {
    this.anchorMatchWholeWordMetadata = anchorMatchWholeWordMetadata;
  }

  /**
   * anchorString.
   *
   * @return Date
   */
  public Date anchorString(String anchorString) {
    this.anchorString = anchorString;
    return this;
  }

  /**
   * Anchor text information for a radio button..
   *
   * @return anchorString
   */
  @ApiModelProperty(value = "Anchor text information for a radio button.")
  public String getAnchorString() {
    return anchorString;
  }

  /** setAnchorString. */
  public void setAnchorString(String anchorString) {
    this.anchorString = anchorString;
  }

  /**
   * anchorStringMetadata.
   *
   * @return Date
   */
  public Date anchorStringMetadata(PropertyMetadata anchorStringMetadata) {
    this.anchorStringMetadata = anchorStringMetadata;
    return this;
  }

  /**
   * Get anchorStringMetadata.
   *
   * @return anchorStringMetadata
   */
  @ApiModelProperty(value = "")
  public PropertyMetadata getAnchorStringMetadata() {
    return anchorStringMetadata;
  }

  /** setAnchorStringMetadata. */
  public void setAnchorStringMetadata(PropertyMetadata anchorStringMetadata) {
    this.anchorStringMetadata = anchorStringMetadata;
  }

  /**
   * anchorTabProcessorVersion.
   *
   * @return Date
   */
  public Date anchorTabProcessorVersion(String anchorTabProcessorVersion) {
    this.anchorTabProcessorVersion = anchorTabProcessorVersion;
    return this;
  }

  /**
   * .
   *
   * @return anchorTabProcessorVersion
   */
  @ApiModelProperty(value = "")
  public String getAnchorTabProcessorVersion() {
    return anchorTabProcessorVersion;
  }

  /** setAnchorTabProcessorVersion. */
  public void setAnchorTabProcessorVersion(String anchorTabProcessorVersion) {
    this.anchorTabProcessorVersion = anchorTabProcessorVersion;
  }

  /**
   * anchorTabProcessorVersionMetadata.
   *
   * @return Date
   */
  public Date anchorTabProcessorVersionMetadata(
      PropertyMetadata anchorTabProcessorVersionMetadata) {
    this.anchorTabProcessorVersionMetadata = anchorTabProcessorVersionMetadata;
    return this;
  }

  /**
   * Get anchorTabProcessorVersionMetadata.
   *
   * @return anchorTabProcessorVersionMetadata
   */
  @ApiModelProperty(value = "")
  public PropertyMetadata getAnchorTabProcessorVersionMetadata() {
    return anchorTabProcessorVersionMetadata;
  }

  /** setAnchorTabProcessorVersionMetadata. */
  public void setAnchorTabProcessorVersionMetadata(
      PropertyMetadata anchorTabProcessorVersionMetadata) {
    this.anchorTabProcessorVersionMetadata = anchorTabProcessorVersionMetadata;
  }

  /**
   * anchorUnits.
   *
   * @return Date
   */
  public Date anchorUnits(String anchorUnits) {
    this.anchorUnits = anchorUnits;
    return this;
  }

  /**
   * Specifies units of the X and Y offset. Units could be pixels, millimeters, centimeters, or
   * inches..
   *
   * @return anchorUnits
   */
  @ApiModelProperty(
      value =
          "Specifies units of the X and Y offset. Units could be pixels, millimeters, centimeters, or inches.")
  public String getAnchorUnits() {
    return anchorUnits;
  }

  /** setAnchorUnits. */
  public void setAnchorUnits(String anchorUnits) {
    this.anchorUnits = anchorUnits;
  }

  /**
   * anchorUnitsMetadata.
   *
   * @return Date
   */
  public Date anchorUnitsMetadata(PropertyMetadata anchorUnitsMetadata) {
    this.anchorUnitsMetadata = anchorUnitsMetadata;
    return this;
  }

  /**
   * Get anchorUnitsMetadata.
   *
   * @return anchorUnitsMetadata
   */
  @ApiModelProperty(value = "")
  public PropertyMetadata getAnchorUnitsMetadata() {
    return anchorUnitsMetadata;
  }

  /** setAnchorUnitsMetadata. */
  public void setAnchorUnitsMetadata(PropertyMetadata anchorUnitsMetadata) {
    this.anchorUnitsMetadata = anchorUnitsMetadata;
  }

  /**
   * anchorXOffset.
   *
   * @return Date
   */
  public Date anchorXOffset(String anchorXOffset) {
    this.anchorXOffset = anchorXOffset;
    return this;
  }

  /**
   * Specifies the X axis location of the tab, in anchorUnits, relative to the anchorString..
   *
   * @return anchorXOffset
   */
  @ApiModelProperty(
      value =
          "Specifies the X axis location of the tab, in anchorUnits, relative to the anchorString.")
  public String getAnchorXOffset() {
    return anchorXOffset;
  }

  /** setAnchorXOffset. */
  public void setAnchorXOffset(String anchorXOffset) {
    this.anchorXOffset = anchorXOffset;
  }

  /**
   * anchorXOffsetMetadata.
   *
   * @return Date
   */
  public Date anchorXOffsetMetadata(PropertyMetadata anchorXOffsetMetadata) {
    this.anchorXOffsetMetadata = anchorXOffsetMetadata;
    return this;
  }

  /**
   * Get anchorXOffsetMetadata.
   *
   * @return anchorXOffsetMetadata
   */
  @ApiModelProperty(value = "")
  public PropertyMetadata getAnchorXOffsetMetadata() {
    return anchorXOffsetMetadata;
  }

  /** setAnchorXOffsetMetadata. */
  public void setAnchorXOffsetMetadata(PropertyMetadata anchorXOffsetMetadata) {
    this.anchorXOffsetMetadata = anchorXOffsetMetadata;
  }

  /**
   * anchorYOffset.
   *
   * @return Date
   */
  public Date anchorYOffset(String anchorYOffset) {
    this.anchorYOffset = anchorYOffset;
    return this;
  }

  /**
   * Specifies the Y axis location of the tab, in anchorUnits, relative to the anchorString..
   *
   * @return anchorYOffset
   */
  @ApiModelProperty(
      value =
          "Specifies the Y axis location of the tab, in anchorUnits, relative to the anchorString.")
  public String getAnchorYOffset() {
    return anchorYOffset;
  }

  /** setAnchorYOffset. */
  public void setAnchorYOffset(String anchorYOffset) {
    this.anchorYOffset = anchorYOffset;
  }

  /**
   * anchorYOffsetMetadata.
   *
   * @return Date
   */
  public Date anchorYOffsetMetadata(PropertyMetadata anchorYOffsetMetadata) {
    this.anchorYOffsetMetadata = anchorYOffsetMetadata;
    return this;
  }

  /**
   * Get anchorYOffsetMetadata.
   *
   * @return anchorYOffsetMetadata
   */
  @ApiModelProperty(value = "")
  public PropertyMetadata getAnchorYOffsetMetadata() {
    return anchorYOffsetMetadata;
  }

  /** setAnchorYOffsetMetadata. */
  public void setAnchorYOffsetMetadata(PropertyMetadata anchorYOffsetMetadata) {
    this.anchorYOffsetMetadata = anchorYOffsetMetadata;
  }

  /**
   * bold.
   *
   * @return Date
   */
  public Date bold(String bold) {
    this.bold = bold;
    return this;
  }

  /**
   * When set to **true**, the information in the tab is bold..
   *
   * @return bold
   */
  @ApiModelProperty(value = "When set to **true**, the information in the tab is bold.")
  public String getBold() {
    return bold;
  }

  /** setBold. */
  public void setBold(String bold) {
    this.bold = bold;
  }

  /**
   * boldMetadata.
   *
   * @return Date
   */
  public Date boldMetadata(PropertyMetadata boldMetadata) {
    this.boldMetadata = boldMetadata;
    return this;
  }

  /**
   * Get boldMetadata.
   *
   * @return boldMetadata
   */
  @ApiModelProperty(value = "")
  public PropertyMetadata getBoldMetadata() {
    return boldMetadata;
  }

  /** setBoldMetadata. */
  public void setBoldMetadata(PropertyMetadata boldMetadata) {
    this.boldMetadata = boldMetadata;
  }

  /**
   * caption.
   *
   * @return Date
   */
  public Date caption(String caption) {
    this.caption = caption;
    return this;
  }

  /**
   * .
   *
   * @return caption
   */
  @ApiModelProperty(value = "")
  public String getCaption() {
    return caption;
  }

  /** setCaption. */
  public void setCaption(String caption) {
    this.caption = caption;
  }

  /**
   * captionMetadata.
   *
   * @return Date
   */
  public Date captionMetadata(PropertyMetadata captionMetadata) {
    this.captionMetadata = captionMetadata;
    return this;
  }

  /**
   * Get captionMetadata.
   *
   * @return captionMetadata
   */
  @ApiModelProperty(value = "")
  public PropertyMetadata getCaptionMetadata() {
    return captionMetadata;
  }

  /** setCaptionMetadata. */
  public void setCaptionMetadata(PropertyMetadata captionMetadata) {
    this.captionMetadata = captionMetadata;
  }

  /**
   * concealValueOnDocument.
   *
   * @return Date
   */
  public Date concealValueOnDocument(String concealValueOnDocument) {
    this.concealValueOnDocument = concealValueOnDocument;
    return this;
  }

  /**
   * When set to **true**, the field appears normally while the recipient is adding or modifying the
   * information in the field, but the data is not visible (the characters are hidden by asterisks)
   * to any other signer or the sender. When an envelope is completed the information is available
   * to the sender through the Form Data link in the DocuSign Console. This setting applies only to
   * text boxes and does not affect list boxes, radio buttons, or check boxes..
   *
   * @return concealValueOnDocument
   */
  @ApiModelProperty(
      value =
          "When set to **true**, the field appears normally while the recipient is adding or modifying the information in the field, but the data is not visible (the characters are hidden by asterisks) to any other signer or the sender.  When an envelope is completed the information is available to the sender through the Form Data link in the DocuSign Console.  This setting applies only to text boxes and does not affect list boxes, radio buttons, or check boxes.")
  public String getConcealValueOnDocument() {
    return concealValueOnDocument;
  }

  /** setConcealValueOnDocument. */
  public void setConcealValueOnDocument(String concealValueOnDocument) {
    this.concealValueOnDocument = concealValueOnDocument;
  }

  /**
   * concealValueOnDocumentMetadata.
   *
   * @return Date
   */
  public Date concealValueOnDocumentMetadata(PropertyMetadata concealValueOnDocumentMetadata) {
    this.concealValueOnDocumentMetadata = concealValueOnDocumentMetadata;
    return this;
  }

  /**
   * Get concealValueOnDocumentMetadata.
   *
   * @return concealValueOnDocumentMetadata
   */
  @ApiModelProperty(value = "")
  public PropertyMetadata getConcealValueOnDocumentMetadata() {
    return concealValueOnDocumentMetadata;
  }

  /** setConcealValueOnDocumentMetadata. */
  public void setConcealValueOnDocumentMetadata(PropertyMetadata concealValueOnDocumentMetadata) {
    this.concealValueOnDocumentMetadata = concealValueOnDocumentMetadata;
  }

  /**
   * conditionalParentLabel.
   *
   * @return Date
   */
  public Date conditionalParentLabel(String conditionalParentLabel) {
    this.conditionalParentLabel = conditionalParentLabel;
    return this;
  }

  /**
   * For conditional fields this is the TabLabel of the parent tab that controls this tab's
   * visibility..
   *
   * @return conditionalParentLabel
   */
  @ApiModelProperty(
      value =
          "For conditional fields this is the TabLabel of the parent tab that controls this tab's visibility.")
  public String getConditionalParentLabel() {
    return conditionalParentLabel;
  }

  /** setConditionalParentLabel. */
  public void setConditionalParentLabel(String conditionalParentLabel) {
    this.conditionalParentLabel = conditionalParentLabel;
  }

  /**
   * conditionalParentLabelMetadata.
   *
   * @return Date
   */
  public Date conditionalParentLabelMetadata(PropertyMetadata conditionalParentLabelMetadata) {
    this.conditionalParentLabelMetadata = conditionalParentLabelMetadata;
    return this;
  }

  /**
   * Get conditionalParentLabelMetadata.
   *
   * @return conditionalParentLabelMetadata
   */
  @ApiModelProperty(value = "")
  public PropertyMetadata getConditionalParentLabelMetadata() {
    return conditionalParentLabelMetadata;
  }

  /** setConditionalParentLabelMetadata. */
  public void setConditionalParentLabelMetadata(PropertyMetadata conditionalParentLabelMetadata) {
    this.conditionalParentLabelMetadata = conditionalParentLabelMetadata;
  }

  /**
   * conditionalParentValue.
   *
   * @return Date
   */
  public Date conditionalParentValue(String conditionalParentValue) {
    this.conditionalParentValue = conditionalParentValue;
    return this;
  }

  /**
   * For conditional fields, this is the value of the parent tab that controls the tab's visibility.
   * If the parent tab is a Checkbox, Radio button, Optional Signature, or Optional Initial use
   * \"on\" as the value to show that the parent tab is active. .
   *
   * @return conditionalParentValue
   */
  @ApiModelProperty(
      value =
          "For conditional fields, this is the value of the parent tab that controls the tab's visibility.  If the parent tab is a Checkbox, Radio button, Optional Signature, or Optional Initial use \"on\" as the value to show that the parent tab is active. ")
  public String getConditionalParentValue() {
    return conditionalParentValue;
  }

  /** setConditionalParentValue. */
  public void setConditionalParentValue(String conditionalParentValue) {
    this.conditionalParentValue = conditionalParentValue;
  }

  /**
   * conditionalParentValueMetadata.
   *
   * @return Date
   */
  public Date conditionalParentValueMetadata(PropertyMetadata conditionalParentValueMetadata) {
    this.conditionalParentValueMetadata = conditionalParentValueMetadata;
    return this;
  }

  /**
   * Get conditionalParentValueMetadata.
   *
   * @return conditionalParentValueMetadata
   */
  @ApiModelProperty(value = "")
  public PropertyMetadata getConditionalParentValueMetadata() {
    return conditionalParentValueMetadata;
  }

  /** setConditionalParentValueMetadata. */
  public void setConditionalParentValueMetadata(PropertyMetadata conditionalParentValueMetadata) {
    this.conditionalParentValueMetadata = conditionalParentValueMetadata;
  }

  /**
   * customTabId.
   *
   * @return Date
   */
  public Date customTabId(String customTabId) {
    this.customTabId = customTabId;
    return this;
  }

  /**
   * The DocuSign generated custom tab ID for the custom tab to be applied. This can only be used
   * when adding new tabs for a recipient. When used, the new tab inherits all the custom tab
   * properties..
   *
   * @return customTabId
   */
  @ApiModelProperty(
      value =
          "The DocuSign generated custom tab ID for the custom tab to be applied. This can only be used when adding new tabs for a recipient. When used, the new tab inherits all the custom tab properties.")
  public String getCustomTabId() {
    return customTabId;
  }

  /** setCustomTabId. */
  public void setCustomTabId(String customTabId) {
    this.customTabId = customTabId;
  }

  /**
   * customTabIdMetadata.
   *
   * @return Date
   */
  public Date customTabIdMetadata(PropertyMetadata customTabIdMetadata) {
    this.customTabIdMetadata = customTabIdMetadata;
    return this;
  }

  /**
   * Get customTabIdMetadata.
   *
   * @return customTabIdMetadata
   */
  @ApiModelProperty(value = "")
  public PropertyMetadata getCustomTabIdMetadata() {
    return customTabIdMetadata;
  }

  /** setCustomTabIdMetadata. */
  public void setCustomTabIdMetadata(PropertyMetadata customTabIdMetadata) {
    this.customTabIdMetadata = customTabIdMetadata;
  }

  /**
   * disableAutoSize.
   *
   * @return Date
   */
  public Date disableAutoSize(String disableAutoSize) {
    this.disableAutoSize = disableAutoSize;
    return this;
  }

  /**
   * When set to **true**, disables the auto sizing of single line text boxes in the signing screen
   * when the signer enters data. If disabled users will only be able enter as much data as the text
   * box can hold. By default this is false. This property only affects single line text boxes..
   *
   * @return disableAutoSize
   */
  @ApiModelProperty(
      value =
          "When set to **true**, disables the auto sizing of single line text boxes in the signing screen when the signer enters data. If disabled users will only be able enter as much data as the text box can hold. By default this is false. This property only affects single line text boxes.")
  public String getDisableAutoSize() {
    return disableAutoSize;
  }

  /** setDisableAutoSize. */
  public void setDisableAutoSize(String disableAutoSize) {
    this.disableAutoSize = disableAutoSize;
  }

  /**
   * disableAutoSizeMetadata.
   *
   * @return Date
   */
  public Date disableAutoSizeMetadata(PropertyMetadata disableAutoSizeMetadata) {
    this.disableAutoSizeMetadata = disableAutoSizeMetadata;
    return this;
  }

  /**
   * Get disableAutoSizeMetadata.
   *
   * @return disableAutoSizeMetadata
   */
  @ApiModelProperty(value = "")
  public PropertyMetadata getDisableAutoSizeMetadata() {
    return disableAutoSizeMetadata;
  }

  /** setDisableAutoSizeMetadata. */
  public void setDisableAutoSizeMetadata(PropertyMetadata disableAutoSizeMetadata) {
    this.disableAutoSizeMetadata = disableAutoSizeMetadata;
  }

  /**
   * documentId.
   *
   * @return Date
   */
  public Date documentId(String documentId) {
    this.documentId = documentId;
    return this;
  }

  /**
   * Specifies the document ID number that the tab is placed on. This must refer to an existing
   * Document's ID attribute..
   *
   * @return documentId
   */
  @ApiModelProperty(
      value =
          "Specifies the document ID number that the tab is placed on. This must refer to an existing Document's ID attribute.")
  public String getDocumentId() {
    return documentId;
  }

  /** setDocumentId. */
  public void setDocumentId(String documentId) {
    this.documentId = documentId;
  }

  /**
   * documentIdMetadata.
   *
   * @return Date
   */
  public Date documentIdMetadata(PropertyMetadata documentIdMetadata) {
    this.documentIdMetadata = documentIdMetadata;
    return this;
  }

  /**
   * Get documentIdMetadata.
   *
   * @return documentIdMetadata
   */
  @ApiModelProperty(value = "")
  public PropertyMetadata getDocumentIdMetadata() {
    return documentIdMetadata;
  }

  /** setDocumentIdMetadata. */
  public void setDocumentIdMetadata(PropertyMetadata documentIdMetadata) {
    this.documentIdMetadata = documentIdMetadata;
  }

  /**
   * errorDetails.
   *
   * @return Date
   */
  public Date errorDetails(ErrorDetails errorDetails) {
    this.errorDetails = errorDetails;
    return this;
  }

  /**
   * Get errorDetails.
   *
   * @return errorDetails
   */
  @ApiModelProperty(value = "")
  public ErrorDetails getErrorDetails() {
    return errorDetails;
  }

  /** setErrorDetails. */
  public void setErrorDetails(ErrorDetails errorDetails) {
    this.errorDetails = errorDetails;
  }

  /**
   * font.
   *
   * @return Date
   */
  public Date font(String font) {
    this.font = font;
    return this;
  }

  /**
   * The font to be used for the tab value. Supported Fonts: Arial, Arial, ArialNarrow, Calibri,
   * CourierNew, Garamond, Georgia, Helvetica, LucidaConsole, Tahoma, TimesNewRoman, Trebuchet,
   * Verdana, MSGothic, MSMincho, Default..
   *
   * @return font
   */
  @ApiModelProperty(
      value =
          "The font to be used for the tab value. Supported Fonts: Arial, Arial, ArialNarrow, Calibri, CourierNew, Garamond, Georgia, Helvetica,   LucidaConsole, Tahoma, TimesNewRoman, Trebuchet, Verdana, MSGothic, MSMincho, Default.")
  public String getFont() {
    return font;
  }

  /** setFont. */
  public void setFont(String font) {
    this.font = font;
  }

  /**
   * fontColor.
   *
   * @return Date
   */
  public Date fontColor(String fontColor) {
    this.fontColor = fontColor;
    return this;
  }

  /**
   * The font color used for the information in the tab. Possible values are: Black, BrightBlue,
   * BrightRed, DarkGreen, DarkRed, Gold, Green, NavyBlue, Purple, or White..
   *
   * @return fontColor
   */
  @ApiModelProperty(
      value =
          "The font color used for the information in the tab.  Possible values are: Black, BrightBlue, BrightRed, DarkGreen, DarkRed, Gold, Green, NavyBlue, Purple, or White.")
  public String getFontColor() {
    return fontColor;
  }

  /** setFontColor. */
  public void setFontColor(String fontColor) {
    this.fontColor = fontColor;
  }

  /**
   * fontColorMetadata.
   *
   * @return Date
   */
  public Date fontColorMetadata(PropertyMetadata fontColorMetadata) {
    this.fontColorMetadata = fontColorMetadata;
    return this;
  }

  /**
   * Get fontColorMetadata.
   *
   * @return fontColorMetadata
   */
  @ApiModelProperty(value = "")
  public PropertyMetadata getFontColorMetadata() {
    return fontColorMetadata;
  }

  /** setFontColorMetadata. */
  public void setFontColorMetadata(PropertyMetadata fontColorMetadata) {
    this.fontColorMetadata = fontColorMetadata;
  }

  /**
   * fontMetadata.
   *
   * @return Date
   */
  public Date fontMetadata(PropertyMetadata fontMetadata) {
    this.fontMetadata = fontMetadata;
    return this;
  }

  /**
   * Get fontMetadata.
   *
   * @return fontMetadata
   */
  @ApiModelProperty(value = "")
  public PropertyMetadata getFontMetadata() {
    return fontMetadata;
  }

  /** setFontMetadata. */
  public void setFontMetadata(PropertyMetadata fontMetadata) {
    this.fontMetadata = fontMetadata;
  }

  /**
   * fontSize.
   *
   * @return Date
   */
  public Date fontSize(String fontSize) {
    this.fontSize = fontSize;
    return this;
  }

  /**
   * The font size used for the information in the tab. Possible values are: Size7, Size8, Size9,
   * Size10, Size11, Size12, Size14, Size16, Size18, Size20, Size22, Size24, Size26, Size28, Size36,
   * Size48, or Size72..
   *
   * @return fontSize
   */
  @ApiModelProperty(
      value =
          "The font size used for the information in the tab.  Possible values are: Size7, Size8, Size9, Size10, Size11, Size12, Size14, Size16, Size18, Size20, Size22, Size24, Size26, Size28, Size36, Size48, or Size72.")
  public String getFontSize() {
    return fontSize;
  }

  /** setFontSize. */
  public void setFontSize(String fontSize) {
    this.fontSize = fontSize;
  }

  /**
   * fontSizeMetadata.
   *
   * @return Date
   */
  public Date fontSizeMetadata(PropertyMetadata fontSizeMetadata) {
    this.fontSizeMetadata = fontSizeMetadata;
    return this;
  }

  /**
   * Get fontSizeMetadata.
   *
   * @return fontSizeMetadata
   */
  @ApiModelProperty(value = "")
  public PropertyMetadata getFontSizeMetadata() {
    return fontSizeMetadata;
  }

  /** setFontSizeMetadata. */
  public void setFontSizeMetadata(PropertyMetadata fontSizeMetadata) {
    this.fontSizeMetadata = fontSizeMetadata;
  }

  /**
   * formOrder.
   *
   * @return Date
   */
  public Date formOrder(String formOrder) {
    this.formOrder = formOrder;
    return this;
  }

  /**
   * .
   *
   * @return formOrder
   */
  @ApiModelProperty(value = "")
  public String getFormOrder() {
    return formOrder;
  }

  /** setFormOrder. */
  public void setFormOrder(String formOrder) {
    this.formOrder = formOrder;
  }

  /**
   * formOrderMetadata.
   *
   * @return Date
   */
  public Date formOrderMetadata(PropertyMetadata formOrderMetadata) {
    this.formOrderMetadata = formOrderMetadata;
    return this;
  }

  /**
   * Get formOrderMetadata.
   *
   * @return formOrderMetadata
   */
  @ApiModelProperty(value = "")
  public PropertyMetadata getFormOrderMetadata() {
    return formOrderMetadata;
  }

  /** setFormOrderMetadata. */
  public void setFormOrderMetadata(PropertyMetadata formOrderMetadata) {
    this.formOrderMetadata = formOrderMetadata;
  }

  /**
   * formPageLabel.
   *
   * @return Date
   */
  public Date formPageLabel(String formPageLabel) {
    this.formPageLabel = formPageLabel;
    return this;
  }

  /**
   * .
   *
   * @return formPageLabel
   */
  @ApiModelProperty(value = "")
  public String getFormPageLabel() {
    return formPageLabel;
  }

  /** setFormPageLabel. */
  public void setFormPageLabel(String formPageLabel) {
    this.formPageLabel = formPageLabel;
  }

  /**
   * formPageLabelMetadata.
   *
   * @return Date
   */
  public Date formPageLabelMetadata(PropertyMetadata formPageLabelMetadata) {
    this.formPageLabelMetadata = formPageLabelMetadata;
    return this;
  }

  /**
   * Get formPageLabelMetadata.
   *
   * @return formPageLabelMetadata
   */
  @ApiModelProperty(value = "")
  public PropertyMetadata getFormPageLabelMetadata() {
    return formPageLabelMetadata;
  }

  /** setFormPageLabelMetadata. */
  public void setFormPageLabelMetadata(PropertyMetadata formPageLabelMetadata) {
    this.formPageLabelMetadata = formPageLabelMetadata;
  }

  /**
   * formPageNumber.
   *
   * @return Date
   */
  public Date formPageNumber(String formPageNumber) {
    this.formPageNumber = formPageNumber;
    return this;
  }

  /**
   * .
   *
   * @return formPageNumber
   */
  @ApiModelProperty(value = "")
  public String getFormPageNumber() {
    return formPageNumber;
  }

  /** setFormPageNumber. */
  public void setFormPageNumber(String formPageNumber) {
    this.formPageNumber = formPageNumber;
  }

  /**
   * formPageNumberMetadata.
   *
   * @return Date
   */
  public Date formPageNumberMetadata(PropertyMetadata formPageNumberMetadata) {
    this.formPageNumberMetadata = formPageNumberMetadata;
    return this;
  }

  /**
   * Get formPageNumberMetadata.
   *
   * @return formPageNumberMetadata
   */
  @ApiModelProperty(value = "")
  public PropertyMetadata getFormPageNumberMetadata() {
    return formPageNumberMetadata;
  }

  /** setFormPageNumberMetadata. */
  public void setFormPageNumberMetadata(PropertyMetadata formPageNumberMetadata) {
    this.formPageNumberMetadata = formPageNumberMetadata;
  }

  /**
   * height.
   *
   * @return Date
   */
  public Date height(String height) {
    this.height = height;
    return this;
  }

  /**
   * Height of the tab in pixels..
   *
   * @return height
   */
  @ApiModelProperty(value = "Height of the tab in pixels.")
  public String getHeight() {
    return height;
  }

  /** setHeight. */
  public void setHeight(String height) {
    this.height = height;
  }

  /**
   * heightMetadata.
   *
   * @return Date
   */
  public Date heightMetadata(PropertyMetadata heightMetadata) {
    this.heightMetadata = heightMetadata;
    return this;
  }

  /**
   * Get heightMetadata.
   *
   * @return heightMetadata
   */
  @ApiModelProperty(value = "")
  public PropertyMetadata getHeightMetadata() {
    return heightMetadata;
  }

  /** setHeightMetadata. */
  public void setHeightMetadata(PropertyMetadata heightMetadata) {
    this.heightMetadata = heightMetadata;
  }

  /**
   * italic.
   *
   * @return Date
   */
  public Date italic(String italic) {
    this.italic = italic;
    return this;
  }

  /**
   * When set to **true**, the information in the tab is italic..
   *
   * @return italic
   */
  @ApiModelProperty(value = "When set to **true**, the information in the tab is italic.")
  public String getItalic() {
    return italic;
  }

  /** setItalic. */
  public void setItalic(String italic) {
    this.italic = italic;
  }

  /**
   * italicMetadata.
   *
   * @return Date
   */
  public Date italicMetadata(PropertyMetadata italicMetadata) {
    this.italicMetadata = italicMetadata;
    return this;
  }

  /**
   * Get italicMetadata.
   *
   * @return italicMetadata
   */
  @ApiModelProperty(value = "")
  public PropertyMetadata getItalicMetadata() {
    return italicMetadata;
  }

  /** setItalicMetadata. */
  public void setItalicMetadata(PropertyMetadata italicMetadata) {
    this.italicMetadata = italicMetadata;
  }

  /**
   * localePolicy.
   *
   * @return Date
   */
  public Date localePolicy(LocalePolicyTab localePolicy) {
    this.localePolicy = localePolicy;
    return this;
  }

  /**
   * Get localePolicy.
   *
   * @return localePolicy
   */
  @ApiModelProperty(value = "")
  public LocalePolicyTab getLocalePolicy() {
    return localePolicy;
  }

  /** setLocalePolicy. */
  public void setLocalePolicy(LocalePolicyTab localePolicy) {
    this.localePolicy = localePolicy;
  }

  /**
   * locked.
   *
   * @return Date
   */
  public Date locked(String locked) {
    this.locked = locked;
    return this;
  }

  /**
   * When set to **true**, the signer cannot change the data of the custom tab..
   *
   * @return locked
   */
  @ApiModelProperty(
      value = "When set to **true**, the signer cannot change the data of the custom tab.")
  public String getLocked() {
    return locked;
  }

  /** setLocked. */
  public void setLocked(String locked) {
    this.locked = locked;
  }

  /**
   * lockedMetadata.
   *
   * @return Date
   */
  public Date lockedMetadata(PropertyMetadata lockedMetadata) {
    this.lockedMetadata = lockedMetadata;
    return this;
  }

  /**
   * Get lockedMetadata.
   *
   * @return lockedMetadata
   */
  @ApiModelProperty(value = "")
  public PropertyMetadata getLockedMetadata() {
    return lockedMetadata;
  }

  /** setLockedMetadata. */
  public void setLockedMetadata(PropertyMetadata lockedMetadata) {
    this.lockedMetadata = lockedMetadata;
  }

  /**
   * maxLength.
   *
   * @return Date
   */
  public Date maxLength(String maxLength) {
    this.maxLength = maxLength;
    return this;
  }

  /**
   * An optional value that describes the maximum length of the property when the property is a
   * string..
   *
   * @return maxLength
   */
  @ApiModelProperty(
      value =
          "An optional value that describes the maximum length of the property when the property is a string.")
  public String getMaxLength() {
    return maxLength;
  }

  /** setMaxLength. */
  public void setMaxLength(String maxLength) {
    this.maxLength = maxLength;
  }

  /**
   * maxLengthMetadata.
   *
   * @return Date
   */
  public Date maxLengthMetadata(PropertyMetadata maxLengthMetadata) {
    this.maxLengthMetadata = maxLengthMetadata;
    return this;
  }

  /**
   * Get maxLengthMetadata.
   *
   * @return maxLengthMetadata
   */
  @ApiModelProperty(value = "")
  public PropertyMetadata getMaxLengthMetadata() {
    return maxLengthMetadata;
  }

  /** setMaxLengthMetadata. */
  public void setMaxLengthMetadata(PropertyMetadata maxLengthMetadata) {
    this.maxLengthMetadata = maxLengthMetadata;
  }

  /**
   * mergeField.
   *
   * @return Date
   */
  public Date mergeField(MergeField mergeField) {
    this.mergeField = mergeField;
    return this;
  }

  /**
   * Get mergeField.
   *
   * @return mergeField
   */
  @ApiModelProperty(value = "")
  public MergeField getMergeField() {
    return mergeField;
  }

  /** setMergeField. */
  public void setMergeField(MergeField mergeField) {
    this.mergeField = mergeField;
  }

  /**
   * mergeFieldXml.
   *
   * @return Date
   */
  public Date mergeFieldXml(String mergeFieldXml) {
    this.mergeFieldXml = mergeFieldXml;
    return this;
  }

  /**
   * .
   *
   * @return mergeFieldXml
   */
  @ApiModelProperty(value = "")
  public String getMergeFieldXml() {
    return mergeFieldXml;
  }

  /** setMergeFieldXml. */
  public void setMergeFieldXml(String mergeFieldXml) {
    this.mergeFieldXml = mergeFieldXml;
  }

  /**
   * name.
   *
   * @return Date
   */
  public Date name(String name) {
    this.name = name;
    return this;
  }

  /**
   * .
   *
   * @return name
   */
  @ApiModelProperty(value = "")
  public String getName() {
    return name;
  }

  /** setName. */
  public void setName(String name) {
    this.name = name;
  }

  /**
   * nameMetadata.
   *
   * @return Date
   */
  public Date nameMetadata(PropertyMetadata nameMetadata) {
    this.nameMetadata = nameMetadata;
    return this;
  }

  /**
   * Get nameMetadata.
   *
   * @return nameMetadata
   */
  @ApiModelProperty(value = "")
  public PropertyMetadata getNameMetadata() {
    return nameMetadata;
  }

  /** setNameMetadata. */
  public void setNameMetadata(PropertyMetadata nameMetadata) {
    this.nameMetadata = nameMetadata;
  }

  /**
   * originalValue.
   *
   * @return Date
   */
  public Date originalValue(String originalValue) {
    this.originalValue = originalValue;
    return this;
  }

  /**
   * The initial value of the tab when it was sent to the recipient. .
   *
   * @return originalValue
   */
  @ApiModelProperty(value = "The initial value of the tab when it was sent to the recipient. ")
  public String getOriginalValue() {
    return originalValue;
  }

  /** setOriginalValue. */
  public void setOriginalValue(String originalValue) {
    this.originalValue = originalValue;
  }

  /**
   * originalValueMetadata.
   *
   * @return Date
   */
  public Date originalValueMetadata(PropertyMetadata originalValueMetadata) {
    this.originalValueMetadata = originalValueMetadata;
    return this;
  }

  /**
   * Get originalValueMetadata.
   *
   * @return originalValueMetadata
   */
  @ApiModelProperty(value = "")
  public PropertyMetadata getOriginalValueMetadata() {
    return originalValueMetadata;
  }

  /** setOriginalValueMetadata. */
  public void setOriginalValueMetadata(PropertyMetadata originalValueMetadata) {
    this.originalValueMetadata = originalValueMetadata;
  }

  /**
   * pageNumber.
   *
   * @return Date
   */
  public Date pageNumber(String pageNumber) {
    this.pageNumber = pageNumber;
    return this;
  }

  /**
   * Specifies the page number on which the tab is located..
   *
   * @return pageNumber
   */
  @ApiModelProperty(value = "Specifies the page number on which the tab is located.")
  public String getPageNumber() {
    return pageNumber;
  }

  /** setPageNumber. */
  public void setPageNumber(String pageNumber) {
    this.pageNumber = pageNumber;
  }

  /**
   * pageNumberMetadata.
   *
   * @return Date
   */
  public Date pageNumberMetadata(PropertyMetadata pageNumberMetadata) {
    this.pageNumberMetadata = pageNumberMetadata;
    return this;
  }

  /**
   * Get pageNumberMetadata.
   *
   * @return pageNumberMetadata
   */
  @ApiModelProperty(value = "")
  public PropertyMetadata getPageNumberMetadata() {
    return pageNumberMetadata;
  }

  /** setPageNumberMetadata. */
  public void setPageNumberMetadata(PropertyMetadata pageNumberMetadata) {
    this.pageNumberMetadata = pageNumberMetadata;
  }

  /**
   * recipientId.
   *
   * @return Date
   */
  public Date recipientId(String recipientId) {
    this.recipientId = recipientId;
    return this;
  }

  /**
   * Unique for the recipient. It is used by the tab element to indicate which recipient is to sign
   * the Document..
   *
   * @return recipientId
   */
  @ApiModelProperty(
      value =
          "Unique for the recipient. It is used by the tab element to indicate which recipient is to sign the Document.")
  public String getRecipientId() {
    return recipientId;
  }

  /** setRecipientId. */
  public void setRecipientId(String recipientId) {
    this.recipientId = recipientId;
  }

  /**
   * recipientIdGuid.
   *
   * @return Date
   */
  public Date recipientIdGuid(String recipientIdGuid) {
    this.recipientIdGuid = recipientIdGuid;
    return this;
  }

  /**
   * .
   *
   * @return recipientIdGuid
   */
  @ApiModelProperty(value = "")
  public String getRecipientIdGuid() {
    return recipientIdGuid;
  }

  /** setRecipientIdGuid. */
  public void setRecipientIdGuid(String recipientIdGuid) {
    this.recipientIdGuid = recipientIdGuid;
  }

  /**
   * recipientIdGuidMetadata.
   *
   * @return Date
   */
  public Date recipientIdGuidMetadata(PropertyMetadata recipientIdGuidMetadata) {
    this.recipientIdGuidMetadata = recipientIdGuidMetadata;
    return this;
  }

  /**
   * Get recipientIdGuidMetadata.
   *
   * @return recipientIdGuidMetadata
   */
  @ApiModelProperty(value = "")
  public PropertyMetadata getRecipientIdGuidMetadata() {
    return recipientIdGuidMetadata;
  }

  /** setRecipientIdGuidMetadata. */
  public void setRecipientIdGuidMetadata(PropertyMetadata recipientIdGuidMetadata) {
    this.recipientIdGuidMetadata = recipientIdGuidMetadata;
  }

  /**
   * recipientIdMetadata.
   *
   * @return Date
   */
  public Date recipientIdMetadata(PropertyMetadata recipientIdMetadata) {
    this.recipientIdMetadata = recipientIdMetadata;
    return this;
  }

  /**
   * Get recipientIdMetadata.
   *
   * @return recipientIdMetadata
   */
  @ApiModelProperty(value = "")
  public PropertyMetadata getRecipientIdMetadata() {
    return recipientIdMetadata;
  }

  /** setRecipientIdMetadata. */
  public void setRecipientIdMetadata(PropertyMetadata recipientIdMetadata) {
    this.recipientIdMetadata = recipientIdMetadata;
  }

  /**
   * requireAll.
   *
   * @return Date
   */
  public Date requireAll(String requireAll) {
    this.requireAll = requireAll;
    return this;
  }

  /**
   * When set to **true** and shared is true, information must be entered in this field to complete
   * the envelope. .
   *
   * @return requireAll
   */
  @ApiModelProperty(
      value =
          "When set to **true** and shared is true, information must be entered in this field to complete the envelope. ")
  public String getRequireAll() {
    return requireAll;
  }

  /** setRequireAll. */
  public void setRequireAll(String requireAll) {
    this.requireAll = requireAll;
  }

  /**
   * requireAllMetadata.
   *
   * @return Date
   */
  public Date requireAllMetadata(PropertyMetadata requireAllMetadata) {
    this.requireAllMetadata = requireAllMetadata;
    return this;
  }

  /**
   * Get requireAllMetadata.
   *
   * @return requireAllMetadata
   */
  @ApiModelProperty(value = "")
  public PropertyMetadata getRequireAllMetadata() {
    return requireAllMetadata;
  }

  /** setRequireAllMetadata. */
  public void setRequireAllMetadata(PropertyMetadata requireAllMetadata) {
    this.requireAllMetadata = requireAllMetadata;
  }

  /**
   * required.
   *
   * @return Date
   */
  public Date required(String required) {
    this.required = required;
    return this;
  }

  /**
   * When set to **true**, the signer is required to fill out this tab.
   *
   * @return required
   */
  @ApiModelProperty(value = "When set to **true**, the signer is required to fill out this tab")
  public String getRequired() {
    return required;
  }

  /** setRequired. */
  public void setRequired(String required) {
    this.required = required;
  }

  /**
   * requiredMetadata.
   *
   * @return Date
   */
  public Date requiredMetadata(PropertyMetadata requiredMetadata) {
    this.requiredMetadata = requiredMetadata;
    return this;
  }

  /**
   * Get requiredMetadata.
   *
   * @return requiredMetadata
   */
  @ApiModelProperty(value = "")
  public PropertyMetadata getRequiredMetadata() {
    return requiredMetadata;
  }

  /** setRequiredMetadata. */
  public void setRequiredMetadata(PropertyMetadata requiredMetadata) {
    this.requiredMetadata = requiredMetadata;
  }

  /**
   * requireInitialOnSharedChange.
   *
   * @return Date
   */
  public Date requireInitialOnSharedChange(String requireInitialOnSharedChange) {
    this.requireInitialOnSharedChange = requireInitialOnSharedChange;
    return this;
  }

  /**
   * Optional element for field markup. When set to **true**, the signer is required to initial when
   * they modify a shared field..
   *
   * @return requireInitialOnSharedChange
   */
  @ApiModelProperty(
      value =
          "Optional element for field markup. When set to **true**, the signer is required to initial when they modify a shared field.")
  public String getRequireInitialOnSharedChange() {
    return requireInitialOnSharedChange;
  }

  /** setRequireInitialOnSharedChange. */
  public void setRequireInitialOnSharedChange(String requireInitialOnSharedChange) {
    this.requireInitialOnSharedChange = requireInitialOnSharedChange;
  }

  /**
   * requireInitialOnSharedChangeMetadata.
   *
   * @return Date
   */
  public Date requireInitialOnSharedChangeMetadata(
      PropertyMetadata requireInitialOnSharedChangeMetadata) {
    this.requireInitialOnSharedChangeMetadata = requireInitialOnSharedChangeMetadata;
    return this;
  }

  /**
   * Get requireInitialOnSharedChangeMetadata.
   *
   * @return requireInitialOnSharedChangeMetadata
   */
  @ApiModelProperty(value = "")
  public PropertyMetadata getRequireInitialOnSharedChangeMetadata() {
    return requireInitialOnSharedChangeMetadata;
  }

  /** setRequireInitialOnSharedChangeMetadata. */
  public void setRequireInitialOnSharedChangeMetadata(
      PropertyMetadata requireInitialOnSharedChangeMetadata) {
    this.requireInitialOnSharedChangeMetadata = requireInitialOnSharedChangeMetadata;
  }

  /**
   * senderRequired.
   *
   * @return Date
   */
  public Date senderRequired(String senderRequired) {
    this.senderRequired = senderRequired;
    return this;
  }

  /**
   * When set to **true**, the sender must populate the tab before an envelope can be sent using the
   * template. This value tab can only be changed by modifying (PUT) the template. Tabs with a
   * `senderRequired` value of true cannot be deleted from an envelope..
   *
   * @return senderRequired
   */
  @ApiModelProperty(
      value =
          "When set to **true**, the sender must populate the tab before an envelope can be sent using the template.   This value tab can only be changed by modifying (PUT) the template.   Tabs with a `senderRequired` value of true cannot be deleted from an envelope.")
  public String getSenderRequired() {
    return senderRequired;
  }

  /** setSenderRequired. */
  public void setSenderRequired(String senderRequired) {
    this.senderRequired = senderRequired;
  }

  /**
   * senderRequiredMetadata.
   *
   * @return Date
   */
  public Date senderRequiredMetadata(PropertyMetadata senderRequiredMetadata) {
    this.senderRequiredMetadata = senderRequiredMetadata;
    return this;
  }

  /**
   * Get senderRequiredMetadata.
   *
   * @return senderRequiredMetadata
   */
  @ApiModelProperty(value = "")
  public PropertyMetadata getSenderRequiredMetadata() {
    return senderRequiredMetadata;
  }

  /** setSenderRequiredMetadata. */
  public void setSenderRequiredMetadata(PropertyMetadata senderRequiredMetadata) {
    this.senderRequiredMetadata = senderRequiredMetadata;
  }

  /**
   * shared.
   *
   * @return Date
   */
  public Date shared(String shared) {
    this.shared = shared;
    return this;
  }

  /**
   * When set to **true**, this custom tab is shared..
   *
   * @return shared
   */
  @ApiModelProperty(value = "When set to **true**, this custom tab is shared.")
  public String getShared() {
    return shared;
  }

  /** setShared. */
  public void setShared(String shared) {
    this.shared = shared;
  }

  /**
   * sharedMetadata.
   *
   * @return Date
   */
  public Date sharedMetadata(PropertyMetadata sharedMetadata) {
    this.sharedMetadata = sharedMetadata;
    return this;
  }

  /**
   * Get sharedMetadata.
   *
   * @return sharedMetadata
   */
  @ApiModelProperty(value = "")
  public PropertyMetadata getSharedMetadata() {
    return sharedMetadata;
  }

  /** setSharedMetadata. */
  public void setSharedMetadata(PropertyMetadata sharedMetadata) {
    this.sharedMetadata = sharedMetadata;
  }

  /**
   * shareToRecipients.
   *
   * @return Date
   */
  public Date shareToRecipients(String shareToRecipients) {
    this.shareToRecipients = shareToRecipients;
    return this;
  }

  /**
   * .
   *
   * @return shareToRecipients
   */
  @ApiModelProperty(value = "")
  public String getShareToRecipients() {
    return shareToRecipients;
  }

  /** setShareToRecipients. */
  public void setShareToRecipients(String shareToRecipients) {
    this.shareToRecipients = shareToRecipients;
  }

  /**
   * shareToRecipientsMetadata.
   *
   * @return Date
   */
  public Date shareToRecipientsMetadata(PropertyMetadata shareToRecipientsMetadata) {
    this.shareToRecipientsMetadata = shareToRecipientsMetadata;
    return this;
  }

  /**
   * Get shareToRecipientsMetadata.
   *
   * @return shareToRecipientsMetadata
   */
  @ApiModelProperty(value = "")
  public PropertyMetadata getShareToRecipientsMetadata() {
    return shareToRecipientsMetadata;
  }

  /** setShareToRecipientsMetadata. */
  public void setShareToRecipientsMetadata(PropertyMetadata shareToRecipientsMetadata) {
    this.shareToRecipientsMetadata = shareToRecipientsMetadata;
  }

  /**
   * smartContractInformation.
   *
   * @return Date
   */
  public Date smartContractInformation(SmartContractInformation smartContractInformation) {
    this.smartContractInformation = smartContractInformation;
    return this;
  }

  /**
   * Get smartContractInformation.
   *
   * @return smartContractInformation
   */
  @ApiModelProperty(value = "")
  public SmartContractInformation getSmartContractInformation() {
    return smartContractInformation;
  }

  /** setSmartContractInformation. */
  public void setSmartContractInformation(SmartContractInformation smartContractInformation) {
    this.smartContractInformation = smartContractInformation;
  }

  /**
   * source.
   *
   * @return Date
   */
  public Date source(String source) {
    this.source = source;
    return this;
  }

  /**
   * .
   *
   * @return source
   */
  @ApiModelProperty(value = "")
  public String getSource() {
    return source;
  }

  /** setSource. */
  public void setSource(String source) {
    this.source = source;
  }

  /**
   * status.
   *
   * @return Date
   */
  public Date status(String status) {
    this.status = status;
    return this;
  }

  /**
   * Indicates the envelope status. Valid values are: * sent - The envelope is sent to the
   * recipients. * created - The envelope is saved as a draft and can be modified and sent later..
   *
   * @return status
   */
  @ApiModelProperty(
      value =
          "Indicates the envelope status. Valid values are:  * sent - The envelope is sent to the recipients.  * created - The envelope is saved as a draft and can be modified and sent later.")
  public String getStatus() {
    return status;
  }

  /** setStatus. */
  public void setStatus(String status) {
    this.status = status;
  }

  /**
   * statusMetadata.
   *
   * @return Date
   */
  public Date statusMetadata(PropertyMetadata statusMetadata) {
    this.statusMetadata = statusMetadata;
    return this;
  }

  /**
   * Get statusMetadata.
   *
   * @return statusMetadata
   */
  @ApiModelProperty(value = "")
  public PropertyMetadata getStatusMetadata() {
    return statusMetadata;
  }

  /** setStatusMetadata. */
  public void setStatusMetadata(PropertyMetadata statusMetadata) {
    this.statusMetadata = statusMetadata;
  }

  /**
   * tabGroupLabels.
   *
   * @return Date
   */
  public Date tabGroupLabels(java.util.List<String> tabGroupLabels) {
    this.tabGroupLabels = tabGroupLabels;
    return this;
  }

  /**
   * addTabGroupLabelsItem.
   *
   * @return Date
   */
  public Date addTabGroupLabelsItem(String tabGroupLabelsItem) {
    if (this.tabGroupLabels == null) {
      this.tabGroupLabels = new java.util.ArrayList<>();
    }
    this.tabGroupLabels.add(tabGroupLabelsItem);
    return this;
  }

  /**
   * .
   *
   * @return tabGroupLabels
   */
  @ApiModelProperty(value = "")
  public java.util.List<String> getTabGroupLabels() {
    return tabGroupLabels;
  }

  /** setTabGroupLabels. */
  public void setTabGroupLabels(java.util.List<String> tabGroupLabels) {
    this.tabGroupLabels = tabGroupLabels;
  }

  /**
   * tabGroupLabelsMetadata.
   *
   * @return Date
   */
  public Date tabGroupLabelsMetadata(PropertyMetadata tabGroupLabelsMetadata) {
    this.tabGroupLabelsMetadata = tabGroupLabelsMetadata;
    return this;
  }

  /**
   * Get tabGroupLabelsMetadata.
   *
   * @return tabGroupLabelsMetadata
   */
  @ApiModelProperty(value = "")
  public PropertyMetadata getTabGroupLabelsMetadata() {
    return tabGroupLabelsMetadata;
  }

  /** setTabGroupLabelsMetadata. */
  public void setTabGroupLabelsMetadata(PropertyMetadata tabGroupLabelsMetadata) {
    this.tabGroupLabelsMetadata = tabGroupLabelsMetadata;
  }

  /**
   * tabId.
   *
   * @return Date
   */
  public Date tabId(String tabId) {
    this.tabId = tabId;
    return this;
  }

  /**
   * The unique identifier for the tab. The tabid can be retrieved with the [ML:GET call]. .
   *
   * @return tabId
   */
  @ApiModelProperty(
      value =
          "The unique identifier for the tab. The tabid can be retrieved with the [ML:GET call].     ")
  public String getTabId() {
    return tabId;
  }

  /** setTabId. */
  public void setTabId(String tabId) {
    this.tabId = tabId;
  }

  /**
   * tabIdMetadata.
   *
   * @return Date
   */
  public Date tabIdMetadata(PropertyMetadata tabIdMetadata) {
    this.tabIdMetadata = tabIdMetadata;
    return this;
  }

  /**
   * Get tabIdMetadata.
   *
   * @return tabIdMetadata
   */
  @ApiModelProperty(value = "")
  public PropertyMetadata getTabIdMetadata() {
    return tabIdMetadata;
  }

  /** setTabIdMetadata. */
  public void setTabIdMetadata(PropertyMetadata tabIdMetadata) {
    this.tabIdMetadata = tabIdMetadata;
  }

  /**
   * tabLabel.
   *
   * @return Date
   */
  public Date tabLabel(String tabLabel) {
    this.tabLabel = tabLabel;
    return this;
  }

  /**
   * The label string associated with the tab..
   *
   * @return tabLabel
   */
  @ApiModelProperty(value = "The label string associated with the tab.")
  public String getTabLabel() {
    return tabLabel;
  }

  /** setTabLabel. */
  public void setTabLabel(String tabLabel) {
    this.tabLabel = tabLabel;
  }

  /**
   * tabLabelMetadata.
   *
   * @return Date
   */
  public Date tabLabelMetadata(PropertyMetadata tabLabelMetadata) {
    this.tabLabelMetadata = tabLabelMetadata;
    return this;
  }

  /**
   * Get tabLabelMetadata.
   *
   * @return tabLabelMetadata
   */
  @ApiModelProperty(value = "")
  public PropertyMetadata getTabLabelMetadata() {
    return tabLabelMetadata;
  }

  /** setTabLabelMetadata. */
  public void setTabLabelMetadata(PropertyMetadata tabLabelMetadata) {
    this.tabLabelMetadata = tabLabelMetadata;
  }

  /**
   * tabOrder.
   *
   * @return Date
   */
  public Date tabOrder(String tabOrder) {
    this.tabOrder = tabOrder;
    return this;
  }

  /**
   * .
   *
   * @return tabOrder
   */
  @ApiModelProperty(value = "")
  public String getTabOrder() {
    return tabOrder;
  }

  /** setTabOrder. */
  public void setTabOrder(String tabOrder) {
    this.tabOrder = tabOrder;
  }

  /**
   * tabOrderMetadata.
   *
   * @return Date
   */
  public Date tabOrderMetadata(PropertyMetadata tabOrderMetadata) {
    this.tabOrderMetadata = tabOrderMetadata;
    return this;
  }

  /**
   * Get tabOrderMetadata.
   *
   * @return tabOrderMetadata
   */
  @ApiModelProperty(value = "")
  public PropertyMetadata getTabOrderMetadata() {
    return tabOrderMetadata;
  }

  /** setTabOrderMetadata. */
  public void setTabOrderMetadata(PropertyMetadata tabOrderMetadata) {
    this.tabOrderMetadata = tabOrderMetadata;
  }

  /**
   * tabType.
   *
   * @return Date
   */
  public Date tabType(String tabType) {
    this.tabType = tabType;
    return this;
  }

  /**
   * .
   *
   * @return tabType
   */
  @ApiModelProperty(value = "")
  public String getTabType() {
    return tabType;
  }

  /** setTabType. */
  public void setTabType(String tabType) {
    this.tabType = tabType;
  }

  /**
   * tabTypeMetadata.
   *
   * @return Date
   */
  public Date tabTypeMetadata(PropertyMetadata tabTypeMetadata) {
    this.tabTypeMetadata = tabTypeMetadata;
    return this;
  }

  /**
   * Get tabTypeMetadata.
   *
   * @return tabTypeMetadata
   */
  @ApiModelProperty(value = "")
  public PropertyMetadata getTabTypeMetadata() {
    return tabTypeMetadata;
  }

  /** setTabTypeMetadata. */
  public void setTabTypeMetadata(PropertyMetadata tabTypeMetadata) {
    this.tabTypeMetadata = tabTypeMetadata;
  }

  /**
   * templateLocked.
   *
   * @return Date
   */
  public Date templateLocked(String templateLocked) {
    this.templateLocked = templateLocked;
    return this;
  }

  /**
   * When set to **true**, the sender cannot change any attributes of the recipient. Used only when
   * working with template recipients. .
   *
   * @return templateLocked
   */
  @ApiModelProperty(
      value =
          "When set to **true**, the sender cannot change any attributes of the recipient. Used only when working with template recipients. ")
  public String getTemplateLocked() {
    return templateLocked;
  }

  /** setTemplateLocked. */
  public void setTemplateLocked(String templateLocked) {
    this.templateLocked = templateLocked;
  }

  /**
   * templateLockedMetadata.
   *
   * @return Date
   */
  public Date templateLockedMetadata(PropertyMetadata templateLockedMetadata) {
    this.templateLockedMetadata = templateLockedMetadata;
    return this;
  }

  /**
   * Get templateLockedMetadata.
   *
   * @return templateLockedMetadata
   */
  @ApiModelProperty(value = "")
  public PropertyMetadata getTemplateLockedMetadata() {
    return templateLockedMetadata;
  }

  /** setTemplateLockedMetadata. */
  public void setTemplateLockedMetadata(PropertyMetadata templateLockedMetadata) {
    this.templateLockedMetadata = templateLockedMetadata;
  }

  /**
   * templateRequired.
   *
   * @return Date
   */
  public Date templateRequired(String templateRequired) {
    this.templateRequired = templateRequired;
    return this;
  }

  /**
   * When set to **true**, the sender may not remove the recipient. Used only when working with
   * template recipients..
   *
   * @return templateRequired
   */
  @ApiModelProperty(
      value =
          "When set to **true**, the sender may not remove the recipient. Used only when working with template recipients.")
  public String getTemplateRequired() {
    return templateRequired;
  }

  /** setTemplateRequired. */
  public void setTemplateRequired(String templateRequired) {
    this.templateRequired = templateRequired;
  }

  /**
   * templateRequiredMetadata.
   *
   * @return Date
   */
  public Date templateRequiredMetadata(PropertyMetadata templateRequiredMetadata) {
    this.templateRequiredMetadata = templateRequiredMetadata;
    return this;
  }

  /**
   * Get templateRequiredMetadata.
   *
   * @return templateRequiredMetadata
   */
  @ApiModelProperty(value = "")
  public PropertyMetadata getTemplateRequiredMetadata() {
    return templateRequiredMetadata;
  }

  /** setTemplateRequiredMetadata. */
  public void setTemplateRequiredMetadata(PropertyMetadata templateRequiredMetadata) {
    this.templateRequiredMetadata = templateRequiredMetadata;
  }

  /**
   * tooltip.
   *
   * @return Date
   */
  public Date tooltip(String tooltip) {
    this.tooltip = tooltip;
    return this;
  }

  /**
   * .
   *
   * @return tooltip
   */
  @ApiModelProperty(value = "")
  public String getTooltip() {
    return tooltip;
  }

  /** setTooltip. */
  public void setTooltip(String tooltip) {
    this.tooltip = tooltip;
  }

  /**
   * toolTipMetadata.
   *
   * @return Date
   */
  public Date toolTipMetadata(PropertyMetadata toolTipMetadata) {
    this.toolTipMetadata = toolTipMetadata;
    return this;
  }

  /**
   * Get toolTipMetadata.
   *
   * @return toolTipMetadata
   */
  @ApiModelProperty(value = "")
  public PropertyMetadata getToolTipMetadata() {
    return toolTipMetadata;
  }

  /** setToolTipMetadata. */
  public void setToolTipMetadata(PropertyMetadata toolTipMetadata) {
    this.toolTipMetadata = toolTipMetadata;
  }

  /**
   * underline.
   *
   * @return Date
   */
  public Date underline(String underline) {
    this.underline = underline;
    return this;
  }

  /**
   * When set to **true**, the information in the tab is underlined..
   *
   * @return underline
   */
  @ApiModelProperty(value = "When set to **true**, the information in the tab is underlined.")
  public String getUnderline() {
    return underline;
  }

  /** setUnderline. */
  public void setUnderline(String underline) {
    this.underline = underline;
  }

  /**
   * underlineMetadata.
   *
   * @return Date
   */
  public Date underlineMetadata(PropertyMetadata underlineMetadata) {
    this.underlineMetadata = underlineMetadata;
    return this;
  }

  /**
   * Get underlineMetadata.
   *
   * @return underlineMetadata
   */
  @ApiModelProperty(value = "")
  public PropertyMetadata getUnderlineMetadata() {
    return underlineMetadata;
  }

  /** setUnderlineMetadata. */
  public void setUnderlineMetadata(PropertyMetadata underlineMetadata) {
    this.underlineMetadata = underlineMetadata;
  }

  /**
   * validationMessage.
   *
   * @return Date
   */
  public Date validationMessage(String validationMessage) {
    this.validationMessage = validationMessage;
    return this;
  }

  /**
   * The message displayed if the custom tab fails input validation (either custom of embedded)..
   *
   * @return validationMessage
   */
  @ApiModelProperty(
      value =
          "The message displayed if the custom tab fails input validation (either custom of embedded).")
  public String getValidationMessage() {
    return validationMessage;
  }

  /** setValidationMessage. */
  public void setValidationMessage(String validationMessage) {
    this.validationMessage = validationMessage;
  }

  /**
   * validationMessageMetadata.
   *
   * @return Date
   */
  public Date validationMessageMetadata(PropertyMetadata validationMessageMetadata) {
    this.validationMessageMetadata = validationMessageMetadata;
    return this;
  }

  /**
   * Get validationMessageMetadata.
   *
   * @return validationMessageMetadata
   */
  @ApiModelProperty(value = "")
  public PropertyMetadata getValidationMessageMetadata() {
    return validationMessageMetadata;
  }

  /** setValidationMessageMetadata. */
  public void setValidationMessageMetadata(PropertyMetadata validationMessageMetadata) {
    this.validationMessageMetadata = validationMessageMetadata;
  }

  /**
   * validationPattern.
   *
   * @return Date
   */
  public Date validationPattern(String validationPattern) {
    this.validationPattern = validationPattern;
    return this;
  }

  /**
   * A regular expression used to validate input for the tab..
   *
   * @return validationPattern
   */
  @ApiModelProperty(value = "A regular expression used to validate input for the tab.")
  public String getValidationPattern() {
    return validationPattern;
  }

  /** setValidationPattern. */
  public void setValidationPattern(String validationPattern) {
    this.validationPattern = validationPattern;
  }

  /**
   * validationPatternMetadata.
   *
   * @return Date
   */
  public Date validationPatternMetadata(PropertyMetadata validationPatternMetadata) {
    this.validationPatternMetadata = validationPatternMetadata;
    return this;
  }

  /**
   * Get validationPatternMetadata.
   *
   * @return validationPatternMetadata
   */
  @ApiModelProperty(value = "")
  public PropertyMetadata getValidationPatternMetadata() {
    return validationPatternMetadata;
  }

  /** setValidationPatternMetadata. */
  public void setValidationPatternMetadata(PropertyMetadata validationPatternMetadata) {
    this.validationPatternMetadata = validationPatternMetadata;
  }

  /**
   * value.
   *
   * @return Date
   */
  public Date value(String value) {
    this.value = value;
    return this;
  }

  /**
   * Specifies the value of the tab. .
   *
   * @return value
   */
  @ApiModelProperty(value = "Specifies the value of the tab. ")
  public String getValue() {
    return value;
  }

  /** setValue. */
  public void setValue(String value) {
    this.value = value;
  }

  /**
   * valueMetadata.
   *
   * @return Date
   */
  public Date valueMetadata(PropertyMetadata valueMetadata) {
    this.valueMetadata = valueMetadata;
    return this;
  }

  /**
   * Get valueMetadata.
   *
   * @return valueMetadata
   */
  @ApiModelProperty(value = "")
  public PropertyMetadata getValueMetadata() {
    return valueMetadata;
  }

  /** setValueMetadata. */
  public void setValueMetadata(PropertyMetadata valueMetadata) {
    this.valueMetadata = valueMetadata;
  }

  /**
   * width.
   *
   * @return Date
   */
  public Date width(String width) {
    this.width = width;
    return this;
  }

  /**
   * Width of the tab in pixels..
   *
   * @return width
   */
  @ApiModelProperty(value = "Width of the tab in pixels.")
  public String getWidth() {
    return width;
  }

  /** setWidth. */
  public void setWidth(String width) {
    this.width = width;
  }

  /**
   * widthMetadata.
   *
   * @return Date
   */
  public Date widthMetadata(PropertyMetadata widthMetadata) {
    this.widthMetadata = widthMetadata;
    return this;
  }

  /**
   * Get widthMetadata.
   *
   * @return widthMetadata
   */
  @ApiModelProperty(value = "")
  public PropertyMetadata getWidthMetadata() {
    return widthMetadata;
  }

  /** setWidthMetadata. */
  public void setWidthMetadata(PropertyMetadata widthMetadata) {
    this.widthMetadata = widthMetadata;
  }

  /**
   * xPosition.
   *
   * @return Date
   */
  public Date xPosition(String xPosition) {
    this.xPosition = xPosition;
    return this;
  }

  /**
   * This indicates the horizontal offset of the object on the page. DocuSign uses 72 DPI when
   * determining position..
   *
   * @return xPosition
   */
  @ApiModelProperty(
      value =
          "This indicates the horizontal offset of the object on the page. DocuSign uses 72 DPI when determining position.")
  public String getXPosition() {
    return xPosition;
  }

  /** setXPosition. */
  public void setXPosition(String xPosition) {
    this.xPosition = xPosition;
  }

  /**
   * xPositionMetadata.
   *
   * @return Date
   */
  public Date xPositionMetadata(PropertyMetadata xPositionMetadata) {
    this.xPositionMetadata = xPositionMetadata;
    return this;
  }

  /**
   * Get xPositionMetadata.
   *
   * @return xPositionMetadata
   */
  @ApiModelProperty(value = "")
  public PropertyMetadata getXPositionMetadata() {
    return xPositionMetadata;
  }

  /** setXPositionMetadata. */
  public void setXPositionMetadata(PropertyMetadata xPositionMetadata) {
    this.xPositionMetadata = xPositionMetadata;
  }

  /**
   * yPosition.
   *
   * @return Date
   */
  public Date yPosition(String yPosition) {
    this.yPosition = yPosition;
    return this;
  }

  /**
   * This indicates the vertical offset of the object on the page. DocuSign uses 72 DPI when
   * determining position..
   *
   * @return yPosition
   */
  @ApiModelProperty(
      value =
          "This indicates the vertical offset of the object on the page. DocuSign uses 72 DPI when determining position.")
  public String getYPosition() {
    return yPosition;
  }

  /** setYPosition. */
  public void setYPosition(String yPosition) {
    this.yPosition = yPosition;
  }

  /**
   * yPositionMetadata.
   *
   * @return Date
   */
  public Date yPositionMetadata(PropertyMetadata yPositionMetadata) {
    this.yPositionMetadata = yPositionMetadata;
    return this;
  }

  /**
   * Get yPositionMetadata.
   *
   * @return yPositionMetadata
   */
  @ApiModelProperty(value = "")
  public PropertyMetadata getYPositionMetadata() {
    return yPositionMetadata;
  }

  /** setYPositionMetadata. */
  public void setYPositionMetadata(PropertyMetadata yPositionMetadata) {
    this.yPositionMetadata = yPositionMetadata;
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
    Date date = (Date) o;
    return Objects.equals(
            this.anchorAllowWhiteSpaceInCharacters, date.anchorAllowWhiteSpaceInCharacters)
        && Objects.equals(
            this.anchorAllowWhiteSpaceInCharactersMetadata,
            date.anchorAllowWhiteSpaceInCharactersMetadata)
        && Objects.equals(this.anchorCaseSensitive, date.anchorCaseSensitive)
        && Objects.equals(this.anchorCaseSensitiveMetadata, date.anchorCaseSensitiveMetadata)
        && Objects.equals(this.anchorHorizontalAlignment, date.anchorHorizontalAlignment)
        && Objects.equals(
            this.anchorHorizontalAlignmentMetadata, date.anchorHorizontalAlignmentMetadata)
        && Objects.equals(this.anchorIgnoreIfNotPresent, date.anchorIgnoreIfNotPresent)
        && Objects.equals(
            this.anchorIgnoreIfNotPresentMetadata, date.anchorIgnoreIfNotPresentMetadata)
        && Objects.equals(this.anchorMatchWholeWord, date.anchorMatchWholeWord)
        && Objects.equals(this.anchorMatchWholeWordMetadata, date.anchorMatchWholeWordMetadata)
        && Objects.equals(this.anchorString, date.anchorString)
        && Objects.equals(this.anchorStringMetadata, date.anchorStringMetadata)
        && Objects.equals(this.anchorTabProcessorVersion, date.anchorTabProcessorVersion)
        && Objects.equals(
            this.anchorTabProcessorVersionMetadata, date.anchorTabProcessorVersionMetadata)
        && Objects.equals(this.anchorUnits, date.anchorUnits)
        && Objects.equals(this.anchorUnitsMetadata, date.anchorUnitsMetadata)
        && Objects.equals(this.anchorXOffset, date.anchorXOffset)
        && Objects.equals(this.anchorXOffsetMetadata, date.anchorXOffsetMetadata)
        && Objects.equals(this.anchorYOffset, date.anchorYOffset)
        && Objects.equals(this.anchorYOffsetMetadata, date.anchorYOffsetMetadata)
        && Objects.equals(this.bold, date.bold)
        && Objects.equals(this.boldMetadata, date.boldMetadata)
        && Objects.equals(this.caption, date.caption)
        && Objects.equals(this.captionMetadata, date.captionMetadata)
        && Objects.equals(this.concealValueOnDocument, date.concealValueOnDocument)
        && Objects.equals(this.concealValueOnDocumentMetadata, date.concealValueOnDocumentMetadata)
        && Objects.equals(this.conditionalParentLabel, date.conditionalParentLabel)
        && Objects.equals(this.conditionalParentLabelMetadata, date.conditionalParentLabelMetadata)
        && Objects.equals(this.conditionalParentValue, date.conditionalParentValue)
        && Objects.equals(this.conditionalParentValueMetadata, date.conditionalParentValueMetadata)
        && Objects.equals(this.customTabId, date.customTabId)
        && Objects.equals(this.customTabIdMetadata, date.customTabIdMetadata)
        && Objects.equals(this.disableAutoSize, date.disableAutoSize)
        && Objects.equals(this.disableAutoSizeMetadata, date.disableAutoSizeMetadata)
        && Objects.equals(this.documentId, date.documentId)
        && Objects.equals(this.documentIdMetadata, date.documentIdMetadata)
        && Objects.equals(this.errorDetails, date.errorDetails)
        && Objects.equals(this.font, date.font)
        && Objects.equals(this.fontColor, date.fontColor)
        && Objects.equals(this.fontColorMetadata, date.fontColorMetadata)
        && Objects.equals(this.fontMetadata, date.fontMetadata)
        && Objects.equals(this.fontSize, date.fontSize)
        && Objects.equals(this.fontSizeMetadata, date.fontSizeMetadata)
        && Objects.equals(this.formOrder, date.formOrder)
        && Objects.equals(this.formOrderMetadata, date.formOrderMetadata)
        && Objects.equals(this.formPageLabel, date.formPageLabel)
        && Objects.equals(this.formPageLabelMetadata, date.formPageLabelMetadata)
        && Objects.equals(this.formPageNumber, date.formPageNumber)
        && Objects.equals(this.formPageNumberMetadata, date.formPageNumberMetadata)
        && Objects.equals(this.height, date.height)
        && Objects.equals(this.heightMetadata, date.heightMetadata)
        && Objects.equals(this.italic, date.italic)
        && Objects.equals(this.italicMetadata, date.italicMetadata)
        && Objects.equals(this.localePolicy, date.localePolicy)
        && Objects.equals(this.locked, date.locked)
        && Objects.equals(this.lockedMetadata, date.lockedMetadata)
        && Objects.equals(this.maxLength, date.maxLength)
        && Objects.equals(this.maxLengthMetadata, date.maxLengthMetadata)
        && Objects.equals(this.mergeField, date.mergeField)
        && Objects.equals(this.mergeFieldXml, date.mergeFieldXml)
        && Objects.equals(this.name, date.name)
        && Objects.equals(this.nameMetadata, date.nameMetadata)
        && Objects.equals(this.originalValue, date.originalValue)
        && Objects.equals(this.originalValueMetadata, date.originalValueMetadata)
        && Objects.equals(this.pageNumber, date.pageNumber)
        && Objects.equals(this.pageNumberMetadata, date.pageNumberMetadata)
        && Objects.equals(this.recipientId, date.recipientId)
        && Objects.equals(this.recipientIdGuid, date.recipientIdGuid)
        && Objects.equals(this.recipientIdGuidMetadata, date.recipientIdGuidMetadata)
        && Objects.equals(this.recipientIdMetadata, date.recipientIdMetadata)
        && Objects.equals(this.requireAll, date.requireAll)
        && Objects.equals(this.requireAllMetadata, date.requireAllMetadata)
        && Objects.equals(this.required, date.required)
        && Objects.equals(this.requiredMetadata, date.requiredMetadata)
        && Objects.equals(this.requireInitialOnSharedChange, date.requireInitialOnSharedChange)
        && Objects.equals(
            this.requireInitialOnSharedChangeMetadata, date.requireInitialOnSharedChangeMetadata)
        && Objects.equals(this.senderRequired, date.senderRequired)
        && Objects.equals(this.senderRequiredMetadata, date.senderRequiredMetadata)
        && Objects.equals(this.shared, date.shared)
        && Objects.equals(this.sharedMetadata, date.sharedMetadata)
        && Objects.equals(this.shareToRecipients, date.shareToRecipients)
        && Objects.equals(this.shareToRecipientsMetadata, date.shareToRecipientsMetadata)
        && Objects.equals(this.smartContractInformation, date.smartContractInformation)
        && Objects.equals(this.source, date.source)
        && Objects.equals(this.status, date.status)
        && Objects.equals(this.statusMetadata, date.statusMetadata)
        && Objects.equals(this.tabGroupLabels, date.tabGroupLabels)
        && Objects.equals(this.tabGroupLabelsMetadata, date.tabGroupLabelsMetadata)
        && Objects.equals(this.tabId, date.tabId)
        && Objects.equals(this.tabIdMetadata, date.tabIdMetadata)
        && Objects.equals(this.tabLabel, date.tabLabel)
        && Objects.equals(this.tabLabelMetadata, date.tabLabelMetadata)
        && Objects.equals(this.tabOrder, date.tabOrder)
        && Objects.equals(this.tabOrderMetadata, date.tabOrderMetadata)
        && Objects.equals(this.tabType, date.tabType)
        && Objects.equals(this.tabTypeMetadata, date.tabTypeMetadata)
        && Objects.equals(this.templateLocked, date.templateLocked)
        && Objects.equals(this.templateLockedMetadata, date.templateLockedMetadata)
        && Objects.equals(this.templateRequired, date.templateRequired)
        && Objects.equals(this.templateRequiredMetadata, date.templateRequiredMetadata)
        && Objects.equals(this.tooltip, date.tooltip)
        && Objects.equals(this.toolTipMetadata, date.toolTipMetadata)
        && Objects.equals(this.underline, date.underline)
        && Objects.equals(this.underlineMetadata, date.underlineMetadata)
        && Objects.equals(this.validationMessage, date.validationMessage)
        && Objects.equals(this.validationMessageMetadata, date.validationMessageMetadata)
        && Objects.equals(this.validationPattern, date.validationPattern)
        && Objects.equals(this.validationPatternMetadata, date.validationPatternMetadata)
        && Objects.equals(this.value, date.value)
        && Objects.equals(this.valueMetadata, date.valueMetadata)
        && Objects.equals(this.width, date.width)
        && Objects.equals(this.widthMetadata, date.widthMetadata)
        && Objects.equals(this.xPosition, date.xPosition)
        && Objects.equals(this.xPositionMetadata, date.xPositionMetadata)
        && Objects.equals(this.yPosition, date.yPosition)
        && Objects.equals(this.yPositionMetadata, date.yPositionMetadata);
  }

  /** Returns the HashCode. */
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
        bold,
        boldMetadata,
        caption,
        captionMetadata,
        concealValueOnDocument,
        concealValueOnDocumentMetadata,
        conditionalParentLabel,
        conditionalParentLabelMetadata,
        conditionalParentValue,
        conditionalParentValueMetadata,
        customTabId,
        customTabIdMetadata,
        disableAutoSize,
        disableAutoSizeMetadata,
        documentId,
        documentIdMetadata,
        errorDetails,
        font,
        fontColor,
        fontColorMetadata,
        fontMetadata,
        fontSize,
        fontSizeMetadata,
        formOrder,
        formOrderMetadata,
        formPageLabel,
        formPageLabelMetadata,
        formPageNumber,
        formPageNumberMetadata,
        height,
        heightMetadata,
        italic,
        italicMetadata,
        localePolicy,
        locked,
        lockedMetadata,
        maxLength,
        maxLengthMetadata,
        mergeField,
        mergeFieldXml,
        name,
        nameMetadata,
        originalValue,
        originalValueMetadata,
        pageNumber,
        pageNumberMetadata,
        recipientId,
        recipientIdGuid,
        recipientIdGuidMetadata,
        recipientIdMetadata,
        requireAll,
        requireAllMetadata,
        required,
        requiredMetadata,
        requireInitialOnSharedChange,
        requireInitialOnSharedChangeMetadata,
        senderRequired,
        senderRequiredMetadata,
        shared,
        sharedMetadata,
        shareToRecipients,
        shareToRecipientsMetadata,
        smartContractInformation,
        source,
        status,
        statusMetadata,
        tabGroupLabels,
        tabGroupLabelsMetadata,
        tabId,
        tabIdMetadata,
        tabLabel,
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
        underline,
        underlineMetadata,
        validationMessage,
        validationMessageMetadata,
        validationPattern,
        validationPatternMetadata,
        value,
        valueMetadata,
        width,
        widthMetadata,
        xPosition,
        xPositionMetadata,
        yPosition,
        yPositionMetadata);
  }

  /** Converts the given object to string. */
  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class Date {\n");

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
    sb.append("    bold: ").append(toIndentedString(bold)).append("\n");
    sb.append("    boldMetadata: ").append(toIndentedString(boldMetadata)).append("\n");
    sb.append("    caption: ").append(toIndentedString(caption)).append("\n");
    sb.append("    captionMetadata: ").append(toIndentedString(captionMetadata)).append("\n");
    sb.append("    concealValueOnDocument: ")
        .append(toIndentedString(concealValueOnDocument))
        .append("\n");
    sb.append("    concealValueOnDocumentMetadata: ")
        .append(toIndentedString(concealValueOnDocumentMetadata))
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
    sb.append("    disableAutoSize: ").append(toIndentedString(disableAutoSize)).append("\n");
    sb.append("    disableAutoSizeMetadata: ")
        .append(toIndentedString(disableAutoSizeMetadata))
        .append("\n");
    sb.append("    documentId: ").append(toIndentedString(documentId)).append("\n");
    sb.append("    documentIdMetadata: ").append(toIndentedString(documentIdMetadata)).append("\n");
    sb.append("    errorDetails: ").append(toIndentedString(errorDetails)).append("\n");
    sb.append("    font: ").append(toIndentedString(font)).append("\n");
    sb.append("    fontColor: ").append(toIndentedString(fontColor)).append("\n");
    sb.append("    fontColorMetadata: ").append(toIndentedString(fontColorMetadata)).append("\n");
    sb.append("    fontMetadata: ").append(toIndentedString(fontMetadata)).append("\n");
    sb.append("    fontSize: ").append(toIndentedString(fontSize)).append("\n");
    sb.append("    fontSizeMetadata: ").append(toIndentedString(fontSizeMetadata)).append("\n");
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
    sb.append("    italic: ").append(toIndentedString(italic)).append("\n");
    sb.append("    italicMetadata: ").append(toIndentedString(italicMetadata)).append("\n");
    sb.append("    localePolicy: ").append(toIndentedString(localePolicy)).append("\n");
    sb.append("    locked: ").append(toIndentedString(locked)).append("\n");
    sb.append("    lockedMetadata: ").append(toIndentedString(lockedMetadata)).append("\n");
    sb.append("    maxLength: ").append(toIndentedString(maxLength)).append("\n");
    sb.append("    maxLengthMetadata: ").append(toIndentedString(maxLengthMetadata)).append("\n");
    sb.append("    mergeField: ").append(toIndentedString(mergeField)).append("\n");
    sb.append("    mergeFieldXml: ").append(toIndentedString(mergeFieldXml)).append("\n");
    sb.append("    name: ").append(toIndentedString(name)).append("\n");
    sb.append("    nameMetadata: ").append(toIndentedString(nameMetadata)).append("\n");
    sb.append("    originalValue: ").append(toIndentedString(originalValue)).append("\n");
    sb.append("    originalValueMetadata: ")
        .append(toIndentedString(originalValueMetadata))
        .append("\n");
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
    sb.append("    requireAll: ").append(toIndentedString(requireAll)).append("\n");
    sb.append("    requireAllMetadata: ").append(toIndentedString(requireAllMetadata)).append("\n");
    sb.append("    required: ").append(toIndentedString(required)).append("\n");
    sb.append("    requiredMetadata: ").append(toIndentedString(requiredMetadata)).append("\n");
    sb.append("    requireInitialOnSharedChange: ")
        .append(toIndentedString(requireInitialOnSharedChange))
        .append("\n");
    sb.append("    requireInitialOnSharedChangeMetadata: ")
        .append(toIndentedString(requireInitialOnSharedChangeMetadata))
        .append("\n");
    sb.append("    senderRequired: ").append(toIndentedString(senderRequired)).append("\n");
    sb.append("    senderRequiredMetadata: ")
        .append(toIndentedString(senderRequiredMetadata))
        .append("\n");
    sb.append("    shared: ").append(toIndentedString(shared)).append("\n");
    sb.append("    sharedMetadata: ").append(toIndentedString(sharedMetadata)).append("\n");
    sb.append("    shareToRecipients: ").append(toIndentedString(shareToRecipients)).append("\n");
    sb.append("    shareToRecipientsMetadata: ")
        .append(toIndentedString(shareToRecipientsMetadata))
        .append("\n");
    sb.append("    smartContractInformation: ")
        .append(toIndentedString(smartContractInformation))
        .append("\n");
    sb.append("    source: ").append(toIndentedString(source)).append("\n");
    sb.append("    status: ").append(toIndentedString(status)).append("\n");
    sb.append("    statusMetadata: ").append(toIndentedString(statusMetadata)).append("\n");
    sb.append("    tabGroupLabels: ").append(toIndentedString(tabGroupLabels)).append("\n");
    sb.append("    tabGroupLabelsMetadata: ")
        .append(toIndentedString(tabGroupLabelsMetadata))
        .append("\n");
    sb.append("    tabId: ").append(toIndentedString(tabId)).append("\n");
    sb.append("    tabIdMetadata: ").append(toIndentedString(tabIdMetadata)).append("\n");
    sb.append("    tabLabel: ").append(toIndentedString(tabLabel)).append("\n");
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
    sb.append("    underline: ").append(toIndentedString(underline)).append("\n");
    sb.append("    underlineMetadata: ").append(toIndentedString(underlineMetadata)).append("\n");
    sb.append("    validationMessage: ").append(toIndentedString(validationMessage)).append("\n");
    sb.append("    validationMessageMetadata: ")
        .append(toIndentedString(validationMessageMetadata))
        .append("\n");
    sb.append("    validationPattern: ").append(toIndentedString(validationPattern)).append("\n");
    sb.append("    validationPatternMetadata: ")
        .append(toIndentedString(validationPatternMetadata))
        .append("\n");
    sb.append("    value: ").append(toIndentedString(value)).append("\n");
    sb.append("    valueMetadata: ").append(toIndentedString(valueMetadata)).append("\n");
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
