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

import android.hardware.fingerprint.FingerprintManager;
import android.os.CancellationSignal;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.TextView;
import oracle.idm.auth.plugin.util.ResourceHelper;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Small helper class to manage text/icon around fingerprint authentication UI.
 */
public class FingerprintUiHelper extends FingerprintManager.AuthenticationCallback {
  /**
   * Constructor for {@link FingerprintUiHelper}.
   */
  FingerprintUiHelper(FingerprintManager fingerprintManager,
                      ImageView icon,
                      TextView errorTextView,
                      Button usePinBtn,
                      FingerprintPromptLocalizedStrings localizedStrings,
                      Callback callback) {
    this._fingerprintManager = fingerprintManager;
    this._icon = icon;
    this._errorTextView = errorTextView;
    this._usePinBtn = usePinBtn;
    this._callback = callback;
    this._localizedStrings = localizedStrings;
  }

  public interface Callback {

    void onAuthenticated();

    void onError();
  }

  public boolean isFingerprintAuthAvailable() {
    // The line below prevents the false positive inspection from Android Studio
    // noinspection ResourceType
    return _fingerprintManager.isHardwareDetected()
        && _fingerprintManager.hasEnrolledFingerprints();
  }

  public void startListening(FingerprintManager.CryptoObject cryptoObject) {
    if (!isFingerprintAuthAvailable()) {
      return;
    }
    _cancellationSignal = new CancellationSignal();
    _selfCancelled.set(false);
    // The line below prevents the false positive inspection from Android Studio
    // noinspection ResourceType
    _fingerprintManager
        .authenticate(cryptoObject, _cancellationSignal, 0 /* flags */, this, null);
    _icon.setImageResource(_R.getDrawable(_FINGERPRINT_ICON));
  }

  public void stopListening() {
    if (_cancellationSignal != null) {
      _selfCancelled.set(true);
      _cancellationSignal.cancel();
      _cancellationSignal = null;
    }
  }

  @Override
  public void onAuthenticationError(int errMsgId, CharSequence errString) {
    Log.e(TAG, "onAuthenticationError: errString = " + errString + " selfCancelled = " + _selfCancelled);
    /*In Xiaomi Redmi Note 3 (Android 6.0.1), onAuthenticationError
     * is called twice immediately one after another when maximum
     * number of attempts is reached. So, uses AtomicBoolean to show the
     * error and dismiss the fragment just once.
     * Bug 25725204 - OMA ANDROID: APP CRASHES WHEN TRYING TO UNLOCK WITH INVALID FIGURE PRINT,
     * */
    if (_selfCancelled.compareAndSet(false, true)) {
      _showError(errString);
      _icon.postDelayed(() -> _callback.onError(), ERROR_TIMEOUT_MILLIS);
    }
  }

  @Override
  public void onAuthenticationHelp(int helpMsgId, CharSequence helpString) {
    _showError(helpString);
  }

  @Override
  public void onAuthenticationFailed() {
    _showError(_localizedStrings.getErrorMessage(_R.getString(_FINGERPRINT_ERROR_STR)));
  }

  @Override
  public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
    _errorTextView.removeCallbacks(_resetErrorTextRunnable);
    _icon.setImageResource(_R.getDrawable(_FINGERPRINT_SUCCESS_ICON));
    _errorTextView.setTextColor(
        _errorTextView.getResources().getColor(_R.getColor(_SUCCESS_COLOR), null));
    _errorTextView.setText(_localizedStrings.getSuccessMessage(_R.getString(_FINGERPRINT_SUCCESS_STR)));
    _icon.postDelayed(() -> _callback.onAuthenticated(), SUCCESS_DELAY_MILLIS);
  }

  private void _showError(CharSequence error) {
    _icon.setImageResource(_R.getDrawable(FINGERPRINT_ERROR_ICON));
    _errorTextView.setText(error);
    _errorTextView.setTextColor(
        _errorTextView.getResources().getColor(_R.getColor(_WARNING_COLOR), null));
    _errorTextView.removeCallbacks(_resetErrorTextRunnable);
    _errorTextView.postDelayed(_resetErrorTextRunnable, ERROR_TIMEOUT_MILLIS);
    _usePinBtn.setVisibility(View.VISIBLE);
  }

  private Runnable _resetErrorTextRunnable = new Runnable() {
    @Override
    public void run() {
      _errorTextView.setTextColor(
          _errorTextView.getResources().getColor(_R.getColor(_HINT_COLOR), null));
      _errorTextView.setText(_localizedStrings.getHintText(_R.getString(_FINGERPRINT_HINT_STR)));
      _icon.setImageResource(_R.getDrawable(_FINGERPRINT_ICON));
    }
  };

  private final FingerprintManager _fingerprintManager;
  private final FingerprintPromptLocalizedStrings _localizedStrings;
  private final ImageView _icon;
  private final TextView _errorTextView;
  private final Callback _callback;
  private final Button _usePinBtn;
  private CancellationSignal _cancellationSignal;
  private AtomicBoolean _selfCancelled = new AtomicBoolean(false);

  private static final String TAG = FingerprintUiHelper.class.getSimpleName();
  private static final long ERROR_TIMEOUT_MILLIS = 1600;
  private static final long SUCCESS_DELAY_MILLIS = 1300;
  private static final ResourceHelper _R = ResourceHelper.INSTANCE;
  private static final String _FINGERPRINT_ICON = "ic_fp_40px";
  private static final String _FINGERPRINT_SUCCESS_ICON = "ic_fingerprint_success";
  private static final String FINGERPRINT_ERROR_ICON = "ic_fingerprint_error";
  private static final String _FINGERPRINT_SUCCESS_STR = "fingerprint_success";
  private static final String _FINGERPRINT_HINT_STR = "fingerprint_hint";
  private static final String _FINGERPRINT_ERROR_STR = "fingerprint_error";
  private static final String _SUCCESS_COLOR = "success_color";
  private static final String _HINT_COLOR = "hint_color";
  private static final String _WARNING_COLOR = "warning_color";
}

