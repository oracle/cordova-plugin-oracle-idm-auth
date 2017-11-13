/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth;

import java.io.Serializable;
import java.util.Calendar;
import java.util.Date;

/**
 * OMToken class which holds the token name, its value and its expiry time.
 *
 */
public class OMToken implements Serializable {
    //TODO remove the cookie specific attributes from the OMTOken class

    private static final long serialVersionUID = 1464960246265793413L;
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
        this.name = name;
        this.value = tokenValue;
    }

    OMToken(String name, String value, String domain) {
        super();
        this.name = name;
        this.value = value;
        this.domain = domain;
    }

    OMToken(String url, String name, String value, String domain, String path,
            Date expiry, boolean httpOnly, boolean secure) {
        super();
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

    OMToken(String url, String name, String value, String domain, String path,
            int expiryInSeconds, boolean httpOnly, boolean secure) {
        super();
        this.url = url;
        this.name = name;
        this.value = value;
        this.domain = domain;
        this.path = path;
        this.expiryInSecs = expiryInSeconds;
        this.httpOnly = httpOnly;
        this.secure = secure;
        populateExpiryDate();
        cookie = true;
    }

    public OMToken() {
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

        if (expiryTime != null) {
            Date currentTime = Calendar.getInstance().getTime();

            if (currentTime.after(expiryTime) || currentTime.equals(expiryTime)) {
                return true;
            }
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
        StringBuilder builder = new StringBuilder();
        if (cookie) {
            builder.append("OMToken [name=").append(name).append(", domain=")
                    .append(domain).append(", path=").append(path)
                    .append(", httpOnly=").append(httpOnly).append(", secure=")
                    .append(secure).append(", value=").append(value)
                    .append(", expiryTime=").append(expiryTime)
                    .append(", expiryInSecs=").append(expiryInSecs)
                    .append(", url=").append(url).append("]");
        } else {
            builder.append("OMToken [name=").append(name).append(", value=").append(value).append(", expiryTime=").append(expiryTime)
                    .append(", expiryInSecs=").append(expiryInSecs);
        }
        return builder.toString();
    }

}
