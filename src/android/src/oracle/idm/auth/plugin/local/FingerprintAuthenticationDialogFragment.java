/**
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */
/*
 * Copyright (C) 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 */

package oracle.idm.auth.plugin.local;

import android.app.AlertDialog;
import android.app.Dialog;
import android.app.DialogFragment;
import android.content.Context;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.TextView;
import oracle.idm.auth.plugin.util.ResourceHelper;

/**
 * A dialog which uses fingerprint APIs to authenticate the user, and falls back to pin
 * authentication if fingerprint is not available.
 */
public class FingerprintAuthenticationDialogFragment extends DialogFragment implements FingerprintUiHelper.Callback {

  public void setData(Callback callback,
                      FingerprintManager.CryptoObject cryptoObject,
                      FingerprintPromptLocalizedStrings localizedStrings) {
    this._cryptoObject = cryptoObject;
    this._callback = callback;
    this._localizedStrings = localizedStrings;
  }

  @Override
  public void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);

    // Do not create a new Fragment when the Activity is re-created such as orientation changes.
    setRetainInstance(true);
  }

  @Override
  public Dialog onCreateDialog(Bundle savedInstanceState) {
    View v = getActivity().getLayoutInflater().inflate(_R.getLayout(_FINGERPRINT_DIALOG_CONTAINER_LYT), null, false);
    Button usePinBtn =  (Button) v.findViewById(_R.getIdentifier(_USE_PIN_BTN));
    v.findViewById(_R.getIdentifier(_USE_PIN_BTN)).setOnClickListener(view -> _usePinFallback());

    if (_localizedStrings.getPinFallbackButtonLabel() != null)
      usePinBtn.setText(_localizedStrings.getPinFallbackButtonLabel());

    Button cancelBtn = (Button) v.findViewById(_R.getIdentifier(_CANCEL_BTN));
    cancelBtn.setOnClickListener(view -> _cancelAuthentication());

    if (_localizedStrings.getCancelButtonLabel() != null)
      cancelBtn.setText(_localizedStrings.getCancelButtonLabel());

    if (_localizedStrings.getPromptMessage() != null)
      ((TextView) v.findViewById(_R.getIdentifier(_FINGERPRINT_MSG_TXT))).setText(_localizedStrings.getPromptMessage());

    TextView statusText = (TextView) v.findViewById(_R.getIdentifier(_FINGERPRINT_STATUS_TXT));
    statusText.setText(_localizedStrings.getHintText(_R.getString(_FINGERPRINT_HINT_STR)));
    ImageView fingerprintIcon = (ImageView) v.findViewById(_R.getIdentifier(_FINGERPRINT_ICON));
    _fingerprintUiHelper = new FingerprintUiHelper((FingerprintManager) getActivity().getSystemService(Context.FINGERPRINT_SERVICE),
                                                   fingerprintIcon,
                                                   statusText,
                                                   usePinBtn,
                                                   _localizedStrings,
                                                   this);

    AlertDialog alertDialog = new AlertDialog.Builder(getActivity())
        .setTitle(_localizedStrings.getPromptTitle(_R.getString(_FINGERPRINT_DIALOG_TITLE_STR)))
        .setView(v)
        .create();
    alertDialog.setCanceledOnTouchOutside(false);
    setCancelable(false);
    return alertDialog;
  }

  @Override
  public void onResume() {
    super.onResume();
    _fingerprintUiHelper.startListening(_cryptoObject);
  }

  @Override
  public void onPause() {
    super.onPause();
    _fingerprintUiHelper.stopListening();
  }

  @Override
  public void onAuthenticated() {
    Log.v(TAG, "Entering onAuthenticated");
    dismiss();
    _callback.onAuthenticated(_cryptoObject);
  }

  @Override
  public void onError() {
    Log.v(TAG, "Entering onError");
    _usePinFallback();
  }

  /**
   * This interface should be implemented by the initiator of FingerprintAuthenticationDialogFragment.
   */
  public interface Callback {
    /**
     * This is called when user's fingerprint is successfully authenticated by the system.
     * If fingerprint authentication fails, automatic fallback to PIN is already handled.
     *
     * @param cryptoObject
     */
    void onAuthenticated(FingerprintManager.CryptoObject cryptoObject);

    /**
     * This is called fingerprint authentication is cancelled and PIN activity is shown:
     * When user presses "Use PIN" option, or  as part of too many incorrect fingerprint attempts.
     */
    void onPinFallback();

    /**
     * This is called with user cancels the authentication.
     */
    void onCancelled();
  }

  /**
   * Switches to backup (pin) screen. This can happen when the user chooses to use the pin authentication method by
   * pressing the button. This can also happen when the user had too many fingerprint attempts.
   */
  private void _usePinFallback() {
    _dismissDialog();
    _callback.onPinFallback();
  }

  private void _cancelAuthentication() {
    _dismissDialog();
    _callback.onCancelled();
  }

  private void _dismissDialog() {
    dismiss();
    _fingerprintUiHelper.stopListening();
  }

  private FingerprintManager.CryptoObject _cryptoObject;
  private FingerprintUiHelper _fingerprintUiHelper;
  private FingerprintPromptLocalizedStrings _localizedStrings;
  private Callback _callback;

  private static final String TAG = FingerprintAuthenticationDialogFragment.class.getSimpleName();
  private static final String _USE_PIN_BTN = "use_pin_btn";
  private static final String _CANCEL_BTN = "cancel_btn";
  private static final String _FINGERPRINT_DIALOG_CONTAINER_LYT = "fingerprint_dialog_container";
  private static final String _FINGERPRINT_DIALOG_TITLE_STR = "fingerprint_dialog_title";
  private static final String _FINGERPRINT_ICON = "fingerprint_icon";
  private static final String _FINGERPRINT_HINT_STR = "fingerprint_hint";
  private static final String _FINGERPRINT_STATUS_TXT = "fingerprint_status";
  private static final String _FINGERPRINT_MSG_TXT = "fingerprint_description";
  private static final ResourceHelper _R = ResourceHelper.INSTANCE;
}
