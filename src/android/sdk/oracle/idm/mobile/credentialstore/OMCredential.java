/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */

package oracle.idm.mobile.credentialstore;

import android.util.Log;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.Serializable;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import oracle.idm.mobile.util.ArrayUtils;

import static oracle.idm.mobile.OMSecurityConstants.Challenge.IDENTITY_DOMAIN_KEY;
import static oracle.idm.mobile.OMSecurityConstants.Challenge.PASSWORD_KEY;
import static oracle.idm.mobile.OMSecurityConstants.Challenge.USERNAME_KEY;

/**
 * OMCredential class is a credential holder which contains username, password,
 * tenant name and set of properties related the user. This object can be used
 * to store the user credentials information in the credential store.
 *
 *
 */
public class OMCredential implements Serializable
{
    private static final long serialVersionUID = 2424551679503106882L;

    // for logging
    private static final String className = OMCredential.class.getName();
    private static final String PROPERTIES = "properties";

    // BEGIN: Keys against which values are stored in Headed SDK
    private static final String USERNAME = "username";
    private static final String PASSWORD = "password";
    private static final String IDENTITY_DOMAIN = "identityDomain";
    // END: Keys against which values are stored in Headed SDK

    private String userName;
    private transient String userPassword;
    private char[] userPasswordCharArray;
    private String identityDomain;
    private Map<String, String> properties;

    public OMCredential()
    {

    }

    /**
     * Creates {@link OMCredential} object.
     *
     * @param username
     * @param password
     * @param identityDomain
     * @param properties
     */
    public OMCredential(String username, char[] password,
            String identityDomain, Map<String, String> properties)
    {
        this.userName = username;
        this.userPasswordCharArray = password;
        this.identityDomain = identityDomain;
        this.properties = properties;
    }

    /**
     * Creates {@link OMCredential} object.
     *
     * @param username
     * @param password
     * @param identityDomain
     * @param properties
     * @deprecated This accepts password as String as opposed to char[], which
     * is a security concern. Instead use {@link #OMCredential(String, char[], String, Map)}.
     */
    @Deprecated
    public OMCredential(String username, String password,
                        String identityDomain, Map<String, String> properties) {
        this(username, password.toCharArray(), identityDomain, properties);
        this.userPassword = password;
    }

    /**
     * Creates {@link OMCredential} object from its {@link String} representation.
     *
     * @param credentialStr String representation.
     * @deprecated Since password is part of String representation, it leads to security issue
     * that password cannot be zeroed out from memory without relying on garbage collection.
     * Now, this class is made {@link Serializable} to store it persistently.
     */
    @Deprecated
    public OMCredential(String credentialStr)
    {
        this(credentialStr, false);
    }

    /**
     * This is added only for the purpose of creating {@link OMCredential}
     * from its string representation format used by Headed SDK.
     *
     * @param credentialStr
     * @param classicFormat true indicates Headed SDK format,
     *                      false indicates Headless SDK format.
     */
    @Deprecated
    public OMCredential(String credentialStr, boolean classicFormat) {
        populateFields(credentialStr, classicFormat);
    }

    public String getUserName()
    {
        return userName;
    }

    public void setUserName(String userName)
    {
        this.userName = userName;
    }

    /**
     * Returns user's password either in hashed format or plain text.
     * The format information (plaintext or hashing algorithm) which
     * is present in User password field internally is removed.
     *
     * @return
     */
    public char[] getUserPasswordAsCharArray() {
        if (userPasswordCharArray != null && userPasswordCharArray.length != 0) {
            // stripe of the {} from the result
            int indexOfbracket = ArrayUtils.indexOf(userPasswordCharArray, '}');

            if (indexOfbracket != -1) {
                return Arrays.copyOfRange(userPasswordCharArray, indexOfbracket + 1, userPasswordCharArray.length);
            }
        }

        return userPasswordCharArray;
    }

    /**
     * Returns user's password either in hashed format or plain text.
     * The format information (plaintext or hashing algorithm) which
     * is present in User password field internally is removed.
     *
     * @return
     * @deprecated It returns the password as String as opposed to char[]
     * which is a security concern. Instead use {@link #getUserPasswordAsCharArray()}.
     */
    @Deprecated
    public String getUserPassword()
    {
        if (userPassword != null && userPassword.length() != 0)
        {
            // stripe of the {} from the result
            int indexOfbracket = userPassword.indexOf('}');

            if (indexOfbracket != -1)
            {
                return userPassword.substring(indexOfbracket + 1);
            }
        }

        return userPassword;
    }

    /**
     * Sets User's password along with format information.
     *
     * @param userPasswordCharArray
     */
    public void setUserPassword(char[] userPasswordCharArray)
    {
        this.userPasswordCharArray = userPasswordCharArray;
    }

    /**
     * Sets User's password along with format information.
     *
     * @param userPassword
     * @deprecated It accepts the password as String as opposed to char[]
     * which is a security concern. Instead of this use {@link #setUserPassword(char[])}.
     */
    @Deprecated
    public void setUserPassword(String userPassword)
    {
        this.userPassword = userPassword;
    }

    /**
     * Clears the password stored in char[].
     */
    public void invalidateUserPassword() {
        if (userPasswordCharArray != null) {
            Arrays.fill(userPasswordCharArray, ' ');
        }
    }

    public String getIdentityDomain()
    {
        return identityDomain;
    }

    public void setIdentityDomain(String identityDomain)
    {
        this.identityDomain = identityDomain;
    }

    public Map<String, String> getProperties()
    {
        if (properties == null)
        {
            properties = new HashMap<>();
        }

        return properties;
    }

    public void setProperties(Map<String, String> properties)
    {
        this.properties = properties;
    }

    /**
     * Gets User's password along with format information.
     * @hide
     */
    public char[] getRawUserPasswordAsCharArray()
    {
        return userPasswordCharArray;
    }

    /**
     * Gets User's password along with format information.
     * @hide
     * @deprecated It gets the password as String as opposed to char[]
     * which is a security concern. Instead of this, use {@link #getRawUserPasswordAsCharArray()}.
     */
    @Deprecated
    public String getRawUserPassword()
    {
        return userPassword;
    }

    @Deprecated
    void updateValue(String propertyName, String propertyValue)
    {
        if (propertyName.equals(USERNAME_KEY))
        {
            this.userName = propertyValue;
        }
        else if (propertyName.equals(PASSWORD_KEY))
        {
            this.userPassword = propertyValue;
        }
        else if (propertyName.equals(IDENTITY_DOMAIN_KEY))
        {
            this.identityDomain = propertyValue;
        }
        else
        {
            // it belongs to custom property
            getProperties().put(propertyName, propertyValue);
        }
    }

    @Deprecated
    void populateFields(String credentialStr, boolean classicFormat)
    {
        try
        {
            JSONObject jsonObject = new JSONObject(credentialStr);

            if (classicFormat) {
                userName = jsonObject.optString(USERNAME);
                userPassword = jsonObject.optString(PASSWORD);
                identityDomain = jsonObject.optString(IDENTITY_DOMAIN);
            } else {
                userName = jsonObject.optString(USERNAME_KEY);
                userPassword = jsonObject.optString(PASSWORD_KEY);
                identityDomain = jsonObject.optString(IDENTITY_DOMAIN_KEY);
            }

            if (userPassword != null) {
                userPasswordCharArray = userPassword.toCharArray();
            }
            JSONObject propJson = jsonObject.optJSONObject(PROPERTIES);

            if (propJson != null)
            {
                Map<String, String> properties = getProperties();

                for (@SuppressWarnings("unchecked")
                Iterator<String> itr = propJson.keys(); itr.hasNext();)
                {
                    String key = itr.next();
                    String value = propJson.optString(key);

                    properties.put(key, value);
                }
            }
        }
        catch (JSONException e)
        {
            Log.d(className + "_populateFields", e.getLocalizedMessage(), e);
        }
    }
}
