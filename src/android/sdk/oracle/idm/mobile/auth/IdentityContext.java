/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth;

import android.Manifest;
import android.content.Context;
import android.content.pm.PackageManager;
import android.location.Location;
import android.location.LocationListener;
import android.location.LocationManager;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import android.os.Process;
import android.provider.Settings.Secure;
import android.telephony.TelephonyManager;
import android.util.Log;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.Calendar;
import java.util.List;
import java.util.Locale;

import oracle.idm.mobile.OMSecurityConstants;
import oracle.idm.mobile.credentialstore.OMCredentialStore;
import oracle.idm.mobile.crypto.CryptoException;
import oracle.idm.mobile.crypto.CryptoScheme;
import oracle.idm.mobile.crypto.OMCryptoService;
import oracle.idm.mobile.util.DeviceUtil;

/**
 * IdentityContext class collects all the information form the device such as
 * network related, hardware related, OS related, location related etc., which
 * is used for registering the device with the server.
 *
 */
public class IdentityContext {
    private JSONObject deviceFingerPrint = null;
    private static final String TAG = IdentityContext.class.getSimpleName();
    static final String DEVICE_PROFILE = "deviceProfile";
    static final String ANDROID = "Android_";
    static final String PHONE_CARRIER = "PHONE_CARRIER";
    static final String WIFI = "WIFI";

    // OS related
    static final String OS_TYPE = "oracle:idm:claims:client:ostype";
    static final String OS_VERSION = "oracle:idm:claims:client:osversion";
    static final String SDKVERSION = "oracle:idm:claims:client:sdkversion";

    // Hardware related
    static final String IMEI = "oracle:idm:claims:client:imei";
    static final String HARDWARE_ID = "hardwareIds";
    static final String UDID = "oracle:idm:claims:client:udid";
    static final String PHONE_NUMBER = "oracle:idm:claims:client:phonenumber";

    // network related
    static final String MAC_ADDRESS = "oracle:idm:claims:client:macaddress";
    static final String GEO_LOCATION = "oracle:idm:claims:client:geolocation";
    static final String NETWORK_TYPE = "oracle:idm:claims:client:networktype";
    static final String PHONE_CARRIER_NAME = "oracle:idm:claims:client:phonecarriername";
    static final String VPN_ENABLED = "oracle:idm:claims:client:vpnenabled";
    static final String FINGERPRINT = "oracle:idm:claims:client:fingerprint";

    // locale related
    static final String LOCALE = "oracle:idm:claims:client:locale";

    // location related
    static final long LOCATION_STALE_TIMEOUT = 900000;
    // 15*60*1000 milliseconds
    static long TIME_DIFF_GPS_AND_DEVICE = 0;
    /*
     * GPS location time comes independently of the network provider time/device
     * time. So, the difference between these times is calculated, during the
     * first gps location update. From then onwards, this difference is used to
     * determine the actual difference between current device time and time
     * obtained from last known location object.
     */

    // device related
    static final String DEVICE_JAILBROKEN = "oracle:idm:claims:client:jailbroken";

    // For logging
    private static final String className = IdentityContext.class.getName();

    private Context context;
    private List<String> claimAttributes;
    private boolean locationUpdateEnabled;
    private int locationTimeout;
    private OMCredentialStore credentialStore;

    public IdentityContext(Context context, OMCredentialStore credentialStore,
                           List<String> claimAttributes, boolean locationUpdateEnabled,
                           int locationTimeout) {
        this.context = context;
        this.credentialStore = credentialStore;
        this.claimAttributes = claimAttributes;
        this.locationUpdateEnabled = locationUpdateEnabled;
        this.locationTimeout = locationTimeout;
    }

    public String getOSType() {
        return ANDROID + Build.VERSION.CODENAME;
    }

    public String getOSVersion() {
        return Build.VERSION.RELEASE;
    }

    public String getClientSDKVersion() {
        return "11.1.2.2.0";
    }

    /**
     * Computes the location information related to the device.
     *
     * @return JSON formatted string
     * @throws JSONException
     */
    private String computeLocationInformation() throws JSONException {
        if (context.checkPermission(Manifest.permission.ACCESS_FINE_LOCATION,
                Process.myPid(), Process.myUid()) == PackageManager.PERMISSION_GRANTED) {
            return new LocationFinder().findLocation(context, locationTimeout);
        }

        return null;
    }

    private class LocationFinder {
        private boolean isLocationAvailable = false;
        private StringBuilder sb = new StringBuilder();
        private LocationManager locationManager;
        private LocationListener locationListener;

        /**
         * Returns the last known location if it is obtained within last
         * LOCATION_STALE_TIMEOUT seconds. Otherwise, requests the system to
         * obtain current location based on the providers enabled.
         */
        public String findLocation(Context context, int locationTimeout) {
            locationManager = (LocationManager) context
                    .getSystemService(Context.LOCATION_SERVICE);

            Location location = null;

            try {
                boolean networkEnabled = locationManager
                        .isProviderEnabled(LocationManager.NETWORK_PROVIDER);

                boolean gpsEnabled = locationManager
                        .isProviderEnabled(LocationManager.GPS_PROVIDER);

                if (gpsEnabled) {
                    // noinspection ResourceType
                    location = locationManager
                            .getLastKnownLocation(LocationManager.GPS_PROVIDER);
                }

                if (location == null && networkEnabled) {
                    // noinspection ResourceType
                    location = locationManager
                            .getLastKnownLocation(LocationManager.NETWORK_PROVIDER);
                }

                boolean requestLocationUpdate = false;
                if (location != null) {
                    long diff = System.currentTimeMillis() - location.getTime();
                    if (location.getProvider().equals("gps")) {
                        diff = diff - IdentityContext.TIME_DIFF_GPS_AND_DEVICE;
                    }

                    if (diff > 0
                            && diff < IdentityContext.LOCATION_STALE_TIMEOUT) {
                        isLocationAvailable = true;
                        String latitude = String
                                .valueOf(location.getLatitude());
                        sb.append(latitude);

                        sb.append(",");

                        String longitude = String.valueOf(location
                                .getLongitude());
                        sb.append(longitude);
                    } else {
                        requestLocationUpdate = true;
                    }
                } else {
                    requestLocationUpdate = true;
                }

                if (requestLocationUpdate) {
                    Log.d(className + "_findLocation",
                            "Request for location update is made");

                    HandlerThread threadWithLooper = new HandlerThread(
                            "ThreadWithLooper");
                    threadWithLooper.start();

                    Looper looper = null;
                    while (looper == null) {
                        looper = threadWithLooper.getLooper();
                    }

                    Handler handler = new Handler(looper);
                    handler.post(new LocationRequestThread(networkEnabled,
                            gpsEnabled));

                    synchronized (this) {
                        Calendar endTime = Calendar.getInstance();
                        endTime.add(Calendar.SECOND, locationTimeout);

                        while (!isLocationAvailable) {
                            try {
                                this.wait(locationTimeout * 1000);
                            } catch (InterruptedException e) {
                                Log.d(className + "_findLocation",
                                        e.getLocalizedMessage(), e);
                            }

                            Calendar currentTime = Calendar.getInstance();

                            if (currentTime.getTime().after(endTime.getTime())) {
                                break;
                            }
                        }
                    }

                    if (locationListener != null) {
                        // noinspection ResourceType
                        locationManager.removeUpdates(locationListener);
                    }

                    threadWithLooper.quit();
                }
            } catch (Exception ex) {
                Log.d(className + "_findLocation", ex.getLocalizedMessage(), ex);
            }

            return sb.toString();
        }

        /**
         * The thread using which location update will be requested
         */
        private class LocationRequestThread implements Runnable {
            private boolean networkEnabled;
            private boolean gpsEnabled;

            private LocationRequestThread(boolean networkEnabled,
                                          boolean gpsEnabled) {
                this.networkEnabled = networkEnabled;
                this.gpsEnabled = gpsEnabled;
            }


            public void run() {
                locationListener = new LocationListener() {
                    @Override
                    public void onLocationChanged(Location location) {
                        // Called when a new location is found by the network
                        // location provider.
                        if (location.getProvider().equals("gps")) {
                            IdentityContext.TIME_DIFF_GPS_AND_DEVICE = System
                                    .currentTimeMillis() - location.getTime();
                        }

                        isLocationAvailable = true;

                        String latitude = String
                                .valueOf(location.getLatitude());
                        sb.append(latitude);

                        sb.append(",");

                        String longitude = String.valueOf(location
                                .getLongitude());
                        sb.append(longitude);
                        // noinspection ResourceType
                        locationManager.removeUpdates(this);

                        synchronized (LocationFinder.this) {
                            LocationFinder.this.notifyAll();
                        }
                    }

                    @Override
                    public void onProviderDisabled(String value) {
                    }

                    @Override
                    public void onProviderEnabled(String value) {
                    }

                    @Override
                    public void onStatusChanged(String value, int pos,
                                                Bundle bundle) {
                    }
                };

                if (gpsEnabled) {
                    // noinspection ResourceType
                    locationManager.requestLocationUpdates(
                            LocationManager.GPS_PROVIDER, 0, 0,
                            locationListener);
                }
                if (networkEnabled) {
                    // noinspection ResourceType
                    locationManager.requestLocationUpdates(
                            LocationManager.NETWORK_PROVIDER, 0, 0,
                            locationListener);
                }
            }
        }
    }

    /**
     * Computes the complete information and returns the JSON
     *
     * @param computeAll If true, it will compute all the claim attributes. Otherwise,
     *                   it just computes GEO_LOCATION & DEVICE_JAILBROKEN and send it
     *                   along with other claim attributes which were computed before
     *                   and is present in cache.
     * @throws JSONException
     */
    private void computeClaims(boolean computeAll) throws JSONException {
        JSONObject deviceProfileJSON;
        boolean isSendAll = false;

        if (claimAttributes.size() == 0) {
            isSendAll = true;
        }
        Log.v(TAG, "isSendAll" + isSendAll);
        Log.v(TAG, "claimAttributes" + claimAttributes);
        if (computeAll
                || (deviceFingerPrint != null && deviceFingerPrint
                .optJSONObject(DEVICE_PROFILE) == null)) {
            deviceFingerPrint = new JSONObject();
            deviceProfileJSON = new JSONObject();

            if (isSendAll || claimAttributes.contains(OS_TYPE)) {
                String codeName = null;
                codeName = ANDROID + Build.VERSION.CODENAME;
                if (codeName != null && codeName.length() > 0) {
                    deviceProfileJSON.put(OS_TYPE, codeName);
                }
            }

            if (isSendAll || claimAttributes.contains(OS_VERSION)) {
                String version = null;
                version = Build.VERSION.RELEASE;
                if (version != null && version.length() > 0) {
                    deviceProfileJSON.put(OS_VERSION, version);
                }
            }

            if (isSendAll || claimAttributes.contains(SDKVERSION)) {
                String sdk = getClientSDKVersion();
                deviceProfileJSON.put(SDKVERSION, sdk);
            }

            TelephonyManager mTelephonyMgr;
            mTelephonyMgr = (TelephonyManager) context
                    .getSystemService(Context.TELEPHONY_SERVICE);
            Log.v(TAG, "claimAttributes.contains(NETWORK_TYPE)" + claimAttributes.contains(NETWORK_TYPE));
            Log.v(TAG, "check network permission" + context.checkPermission(
                    Manifest.permission.ACCESS_NETWORK_STATE,
                    Process.myPid(), Process.myUid()));
            if ((isSendAll || claimAttributes.contains(NETWORK_TYPE))
                    && context.checkPermission(
                    Manifest.permission.ACCESS_NETWORK_STATE,
                    Process.myPid(), Process.myUid()) == PackageManager.PERMISSION_GRANTED) {
                int networkType = mTelephonyMgr.getNetworkType();
                ConnectivityManager connectivityManager = (ConnectivityManager) context
                        .getSystemService(Context.CONNECTIVITY_SERVICE);
                NetworkInfo mobNetInfo = connectivityManager
                        .getNetworkInfo(networkType);
                if (mobNetInfo != null) {
                    String networkTypeName = null;

                    if (mobNetInfo.getType() == ConnectivityManager.TYPE_WIFI
                            || mobNetInfo.getType() == ConnectivityManager.TYPE_WIMAX) {
                        networkTypeName = WIFI;
                    } else {
                        networkTypeName = PHONE_CARRIER;
                    }
                    deviceProfileJSON.put(NETWORK_TYPE, networkTypeName);
                }
            }

            if (isSendAll || claimAttributes.contains(PHONE_CARRIER_NAME)) {
                String carrierName = mTelephonyMgr.getNetworkOperatorName();
                if (carrierName != null && carrierName.length() > 0) {
                    deviceProfileJSON.put(PHONE_CARRIER_NAME, carrierName);
                }
            }

            if (isSendAll || claimAttributes.contains(VPN_ENABLED)) {
                // TODO Have to determine whether VPN is enabled or not
                deviceProfileJSON.put(VPN_ENABLED, false);
            }

            if (isSendAll || claimAttributes.contains(LOCALE)) {

                String localeInfo = Locale.getDefault().toString();
                if (localeInfo != null && localeInfo.length() > 0) {
                    deviceProfileJSON.put(LOCALE, localeInfo);
                }
            }

            JSONObject hardwareJSON = new JSONObject();

            if (context.checkPermission(Manifest.permission.READ_PHONE_STATE,
                    Process.myPid(), Process.myUid()) == PackageManager.PERMISSION_GRANTED) {
                if (isSendAll || claimAttributes.contains(IMEI)) {
                    String imei = mTelephonyMgr.getDeviceId();

                    if (imei != null && imei.length() > 0) {
                        hardwareJSON.put(IMEI, imei);
                    }
                }

                if (isSendAll || claimAttributes.contains(PHONE_NUMBER)) {
                    String phoneNumber = mTelephonyMgr.getLine1Number();
                    if (phoneNumber != null && phoneNumber.length() > 0) {
                        hardwareJSON.put(PHONE_NUMBER, phoneNumber);
                    }
                }
            }

            if (isSendAll || claimAttributes.contains(UDID)) {
                String udid = Secure.ANDROID_ID;
                if (udid != null) {
                    hardwareJSON.put(UDID, udid);
                }
            }

            if (isSendAll || claimAttributes.contains(MAC_ADDRESS)) {
                hardwareJSON.put(MAC_ADDRESS, getMacAddress());
            }

            if (isSendAll || claimAttributes.contains(FINGERPRINT)) {
                String macAddress = getMacAddress();
                String hash = null;

                if (macAddress != null) {
                    OMCryptoService cryptoService = new OMCryptoService(
                            credentialStore);
                    try {
                        hash = cryptoService.hash(macAddress,
                                CryptoScheme.SHA256,
                                OMSecurityConstants.DEFAULT_SALT_LENGTH, false);
                    } catch (CryptoException e) {
                        Log.d(className + "_computeClaims",
                                e.getLocalizedMessage(), e);
                    }
                }
                hardwareJSON.put(FINGERPRINT, hash);
            }

            if (hardwareJSON.length() > 0) {
                deviceProfileJSON.put(HARDWARE_ID, hardwareJSON);
            }
        } else {
            deviceProfileJSON = deviceFingerPrint.optJSONObject(DEVICE_PROFILE);
        }

        if ((isSendAll || claimAttributes.contains(GEO_LOCATION))
                && locationUpdateEnabled) {
            String locationInfo = computeLocationInformation();
            if (locationInfo != null) {
                deviceProfileJSON.put(GEO_LOCATION, locationInfo);
            }
        }

        if (isSendAll || claimAttributes.contains(DEVICE_JAILBROKEN)) {
            deviceProfileJSON.put(DEVICE_JAILBROKEN, DeviceUtil.isDeviceRooted(context));
        }

        deviceFingerPrint.put(DEVICE_PROFILE, deviceProfileJSON);
    }

    private String getMacAddress() {
        Log.v(TAG, "getMacAddress");
        Log.v(TAG, "context.checkPermission(Manifest.permission.ACCESS_WIFI_STATE,\n" +
                "                Process.myPid(), Process.myUid())" + context.checkPermission(Manifest.permission.ACCESS_WIFI_STATE,
                Process.myPid(), Process.myUid()));
        if (context.checkPermission(Manifest.permission.ACCESS_WIFI_STATE,
                Process.myPid(), Process.myUid()) == PackageManager.PERMISSION_GRANTED) {
            Log.v(TAG, "context.checkPermission(Manifest.permission.ACCESS_WIFI_STATE,\n" +
                    "                Process.myPid(), Process.myUid())" + context.checkPermission(Manifest.permission.ACCESS_WIFI_STATE,
                    Process.myPid(), Process.myUid()));
            WifiManager wim = (WifiManager) context
                    .getSystemService(Context.WIFI_SERVICE);
            WifiInfo currentConnectionInfo = wim.getConnectionInfo();

            String macAddressValue = null;
            if (currentConnectionInfo != null) {
                macAddressValue = currentConnectionInfo.getMacAddress();
            }

            if (macAddressValue != null && macAddressValue.trim().length() > 0) {
                Log.v(TAG, "getMacAddress value" + macAddressValue);
                return macAddressValue;
            }
        }

        return null;
    }

    /**
     * Gets the claim attributes values as a JSON Object. If it was computed
     * previously, it will update certain claim attributes. Otherwise, it will
     * compute everything.
     *
     * @return JSON formatted string of device claims.
     */
    public JSONObject getIdentityClaims() {
        Log.v(TAG, "deviceFingerPrint" + deviceFingerPrint);
        try {
            if (deviceFingerPrint == null) {
                computeClaims(true);
            } else {
                computeClaims(false);
            }
        } catch (JSONException ex) {
            Log.d(className + "_getIdentityClaims", ex.getLocalizedMessage(),
                    ex);
            return null;
        }
        return deviceFingerPrint;
    }

}
