package oracle.idm.auth.plugin.local;

public class FingerprintPromptLocalizedStrings {
  private String promptMessage;
  private String pinFallbackButtonLabel;
  private String cancelButtonLabel;
  private String successMessage;
  private String errorMessage;
  private String promptTitle;
  private String hintText;

  public String getPromptMessage() {
    return promptMessage;
  }

  public void setPromptMessage(String promptMessage) {
    this.promptMessage = promptMessage;
  }

  public String getPinFallbackButtonLabel() {
    return pinFallbackButtonLabel;
  }

  public void setPinFallbackButtonLabel(String pinFallbackButtonLabel) {
    this.pinFallbackButtonLabel = pinFallbackButtonLabel;
  }

  public String getCancelButtonLabel() {
    return cancelButtonLabel;
  }

  public void setCancelButtonLabel(String cancelButtonLabel) {
    this.cancelButtonLabel = cancelButtonLabel;
  }

  public String getSuccessMessage(String def) {
    return successMessage == null ? def : successMessage;
  }

  public void setSuccessMessage(String successMessage) {
    this.successMessage = successMessage;
  }

  public String getErrorMessage(String def) {
    return errorMessage == null ? def : errorMessage;
  }

  public void setErrorMessage(String errorMessage) {
    this.errorMessage = errorMessage;
  }

  public String getPromptTitle(String def) {
    return promptTitle == null ? def : promptTitle;
  }

  public void setPromptTitle(String dialogTitle) {
    this.promptTitle = dialogTitle;
  }

  public String getHintText(String def) {
    return hintText == null ? def : hintText;
  }

  public void setHintText(String hintText) {
    this.hintText = hintText;
  }
}
