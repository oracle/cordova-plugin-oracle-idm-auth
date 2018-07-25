/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth;

import java.util.Date;

/**
 * OMCookie class which holds the cookie fields.
 */
public class OMCookie extends OMToken {

    private static final long serialVersionUID = 1464960246265793417L;
    private String url;
    private String domain;
    private String path;
    private boolean httpOnly;
    private boolean secure;
    private String expiryDateStr;


    OMCookie(String name, String value, int expiryInSecs) {
        this.name = name;
        this.value = value;
        this.expiryInSecs = expiryInSecs;
    }

    OMCookie(String name, String tokenValue, Date expiry) {
        this.name = name;
        this.value = tokenValue;
        this.expiryTime = expiry;
    }

    OMCookie(String name, String tokenValue) {
        this.name = name;
        this.value = tokenValue;
    }

    public OMCookie(String name, String value, String domain) {
        super();
        this.name = name;
        this.value = value;
        this.domain = domain;
    }

    /**
     * @param name
     * @param value
     * @param domain
     * @param path
     * @param expiry
     * @param httpOnly
     * @param secure
     * @hide
     */
    public OMCookie(String url, String name, String value, String domain, String path,
                    String expiry, boolean httpOnly, boolean secure) {
        super();
        this.url = url;
        this.name = name;
        this.value = value;
        this.domain = domain;
        this.path = path;
        this.expiryDateStr = expiry;
        this.httpOnly = httpOnly;
        this.secure = secure;
    }

    OMCookie(String url, String name, String value, String domain, String path,
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
    }

    OMCookie() {
    }


    public String getName() {
        return name;
    }

    public String getValue() {
        return value;
    }

    public String getExpiryDateStr() {
        return expiryDateStr;
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

    void setName(String name) {
        this.name = name;
    }

    void setValue(String value) {
        this.value = value;
    }

    void setExpiryTime(Date expiry) {
        this.expiryTime = expiry;
    }

    void setExpiryDateStr(String expiry) {
        this.expiryDateStr = expiry;
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

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

}
