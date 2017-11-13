/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.configuration;

import java.util.Map;

/**
 * OMApplicationProfile class holds the information about the client application
 * which is retrieved from the server.
 * 
 *
 */
public class OMApplicationProfile
{
    private Map<String, String> applicationConfig;
    private String applicationId;

    public OMApplicationProfile(String applicationId,
            Map<String, String> applicationConfig)
    {
        this.applicationId = applicationId;
        this.applicationConfig = applicationConfig;
    }

}
