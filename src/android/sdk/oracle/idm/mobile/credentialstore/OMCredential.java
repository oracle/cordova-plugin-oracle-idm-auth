/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */

package oracle.idm.mobile.credentialstore;
 
import android.util.Log;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import static oracle.idm.mobile.OMSecurityConstants.Challenge.*;

/**
 * OMCredential class is a credential holder which contains username, password,
 * tenant name and set of properties related the user. This object can be used
 * to store the user credentials information in the credential store.
 * 
 *
 */
public class OMCredential
{
    // for logging
    private static final String className = OMCredential.class.getName();
    private static final String PROPERTIES = "properties";
 
    private String userName;
    private String userPassword;
    private String identityDomain;
    private Map<String, String> properties;
 
    public OMCredential()
    {
 
    }
 
    public OMCredential(String username, String password,
            String identityDomain, Map<String, String> properties)
    {
        this.userName = username;
        this.userPassword = password;
        this.identityDomain = identityDomain;
        this.properties = properties;
    }
 
    public OMCredential(String credentialStr)
    {
        populateFields(credentialStr);
    }
 
    public String getUserName()
    {
        return userName;
    }
 
    public void setUserName(String userName)
    {
        this.userName = userName;
    }
 
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
 
    public void setUserPassword(String userPassword)
    {
        this.userPassword = userPassword;
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
     * @hide
     */
    public String getRawUserPassword()
    {
        return userPassword;
    }
 
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
 
    String convertToJSONString()
    {
        JSONObject jsonObject = new JSONObject();
 
        try
        {
            jsonObject.put(USERNAME_KEY, userName);
            jsonObject.put(PASSWORD_KEY, userPassword);
 
            if (identityDomain != null && identityDomain.length() != 0)
            {
                jsonObject.put(IDENTITY_DOMAIN_KEY, identityDomain);
            }
 
            if (!getProperties().isEmpty())
            {
                JSONObject propJson = new JSONObject();
 
                for (Map.Entry<String, String> entry : getProperties()
                        .entrySet())
                {
                    String key = entry.getKey();
                    String value = entry.getValue();
 
                    propJson.put(key, value);
                }
 
                jsonObject.put(PROPERTIES, propJson);
            }
 
        }
        catch (JSONException e)
        {
            Log.d(className + "_convertToJSONString", e.getLocalizedMessage(),
                    e);
        }
 
        return jsonObject.toString();
 
    }
 
    void populateFields(String credentialStr)
    {
        try
        {
            JSONObject jsonObject = new JSONObject(credentialStr);
 
            userName = jsonObject.optString(USERNAME_KEY);
            userPassword = jsonObject.optString(PASSWORD_KEY);
            identityDomain = jsonObject.optString(IDENTITY_DOMAIN_KEY);
 
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
