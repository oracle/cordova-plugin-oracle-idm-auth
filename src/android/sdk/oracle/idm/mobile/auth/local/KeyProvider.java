/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth.local;

import java.security.Key;

/**
 * Key maker abstraction.
 */
public interface KeyProvider {

    Key getKey() throws OMAuthenticationManagerException;
}
