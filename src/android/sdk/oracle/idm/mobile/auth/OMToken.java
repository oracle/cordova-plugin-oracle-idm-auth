/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.Serializable;
import java.util.Calendar;
import java.util.Date;

import oracle.idm.mobile.OMSecurityConstants;
import oracle.idm.mobile.logging.OMLog;

import static oracle.idm.mobile.OMSecurityConstants.DOMAIN;
import static oracle.idm.mobile.OMSecurityConstants.EXPIRY_SECS;
import static oracle.idm.mobile.OMSecurityConstants.HTTP_ONLY;
import static oracle.idm.mobile.OMSecurityConstants.PATH;
import static oracle.idm.mobile.OMSecurityConstants.SECURE;
import static oracle.idm.mobile.OMSecurityConstants.TOKEN_NAME;
import static oracle.idm.mobile.OMSecurityConstants.TOKEN_VALUE;

/**
 * OMToken class which holds the token name, its value and its expiry time.
 *
 */
public class OMToken implements Serializable {
    //TODO remove the cookie specific attributes from the OMTOken class

    private static final long serialVersionUID = 1464960246265793413L;
    private static final String TAG = OMToken.class.getSimpleName();

    private String url;
    private String domain;
    private String path;
    private boolean httpOnly;
    private boolean secure;
    protected String name;
    protected String value;
    protected Date expiryTime;
    protected int expiryInSecs;
    protected boolean cookie = false;

    OMToken(JSONObject token) {
        String url = token.optString(OMSecurityConstants.URL);
        String tokenName = token.optString(TOKEN_NAME, "");
        String tokenValue = token.optString(TOKEN_VALUE, "");
        long expiryStr = token.optLong(EXPIRY_SECS, -1);

        Date expiry = null;
        if (expiryStr != -1) {
            expiry = new Date(expiryStr);
        }

        String domain = token.optString(DOMAIN, null);
        String path = token.optString(PATH, null);
        boolean httpOnly = token.optBoolean(HTTP_ONLY);
        boolean secure = token.optBoolean(SECURE);

        setValues(url, tokenName, tokenValue, domain, path, expiry, httpOnly, secure);
    }

    OMToken(String name, String value, int expiryInSecs) {
        this.name = name;
        this.value = value;
        this.expiryInSecs = expiryInSecs;
        populateExpiryDate();
    }

    protected OMToken(String name, String tokenValue, Date expiry) {
        this.name = name;
        this.value = tokenValue;
        this.expiryTime = expiry;
    }

    protected OMToken(String name, String tokenValue) {
        this(name, tokenValue, null);
    }

    OMToken(String url, String name, String value, String domain, String path,
            Date expiry, boolean httpOnly, boolean secure) {
        setValues(url, name, value, domain, path, expiry, httpOnly, secure);
    }

    OMToken(String url, String name, String value, String domain, String path,
            int expiryInSeconds, boolean httpOnly, boolean secure) {
        setValues(url, name, value, domain, path, null, httpOnly, secure);
        this.expiryInSecs = expiryInSeconds;
        populateExpiryDate();
    }

    public OMToken() {
    }

    private void setValues(String url, String name, String value, String domain, String path,
                           Date expiry, boolean httpOnly, boolean secure) {
        this.url = url;
        this.name = name;
        this.value = value;
        this.domain = domain;
        this.path = path;
        this.expiryTime = expiry;
        this.httpOnly = httpOnly;
        this.secure = secure;
        cookie = true;
    }

    /**
     * Checks whether the token is valid based on the expire time.
     *
     * @return true / false
     */
    public boolean isTokenExpired() {

        if (expiryTime == null) { // Never expires
            return false;
        }

        Date currentTime = Calendar.getInstance().getTime();
        if (currentTime.after(expiryTime) || currentTime.equals(expiryTime)) {
            return true;
        }
        return false;
    }

    protected void populateExpiryDate() {
        if (expiryInSecs > 0) {
            Calendar futureTime = Calendar.getInstance();
            futureTime.add(Calendar.SECOND, expiryInSecs);
            expiryTime = futureTime.getTime();
        }
    }

    // Getter / Setter Methods
    public String getUrl() {
        return url;
    }

    public String getName() {
        return name;
    }

    public String getValue() {
        return value;
    }

    public Date getExpiryTime() {
        return expiryTime;
    }

    public String getDomain() {
        return domain;
    }

    public String getPath() {
        return path;
    }

    public boolean isHttpOnly() {
        return httpOnly;
    }

    public boolean isSecure() {
        return secure;
    }

    void setUrl(String url) {
        this.url = url;
    }

    void setName(String name) {
        this.name = name;
    }

    void setValue(String value) {
        this.value = value;
    }

    void setExpiryTime(Date expiry) {
        this.expiryTime = expiry;
    }

    int getExpiryInSecs() {
        return expiryInSecs;
    }

    void setExpiryInSecs(int expiryInSecs) {
        this.expiryInSecs = expiryInSecs;
    }

    void setHttpOnly(boolean httpOnly) {
        this.httpOnly = httpOnly;
    }

    void setSecure(boolean secure) {
        this.secure = secure;
    }

    @Override
    public String toString() {
        return toJSONObject().toString();
    }

    public JSONObject toJSONObject() {
        JSONObject tokenJson = new JSONObject();
        try {
            tokenJson.put(TOKEN_NAME, name);
            tokenJson.put(TOKEN_VALUE, value);

            if (expiryTime != null) {
                tokenJson.put(EXPIRY_SECS, expiryTime.getTime());
            }

            if (cookie) {
                tokenJson.put(OMSecurityConstants.URL, url);
                if (domain != null) {
                    tokenJson.put(DOMAIN, domain);
                }
                if (path != null) {
                    tokenJson.put(PATH, path);
                }
                tokenJson.put(HTTP_ONLY, httpOnly);
                tokenJson.put(SECURE, secure);
            }
        } catch (JSONException e) {
            OMLog.error(TAG, e.getMessage(), e);
        }
        return tokenJson;
    }

}
