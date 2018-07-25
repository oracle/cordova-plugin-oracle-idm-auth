/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.auth.local;

import android.content.Context;
import android.text.TextUtils;

import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import oracle.idm.mobile.OMErrorCode;

/**
 * <p>
 * Main interface for managing authenticators. {@link OMAuthenticationManager#registerAuthenticator(String, String)} and
 * it's overloaded version is the main point of entry to this class. <code>authenticatorName</code>
 * that is used to uniquely identify an {@link OMAuthenticator} class.
 * </p>
 *
 * A registered authenticator has to be enabled using {@link #enableAuthentication(String)} before it can be used.
 * <p>
 * Most of the times, a client would simply use {@link OMAuthenticationManager#getAuthenticator(String)} or
 * {@link OMAuthenticationManager#getAuthenticator(Class)} to get a 'singleton' instance of an
 * authenticator registered with the name given name or given Class type.
 *
 * <p>
 * For applications that do need multiple instance of a given authenticator or multiple types of
 * authenticators, {@link #enableAuthentication(String, String)} takes the second parameter to
 * uniquely identify an instance of a registered authenticator.
 *
 * <p>
 * {@link #isEnabled(String, String)} is similarly overloaded to support checking for both 'singlton'
 * as well instances of a given authenticator.
 *
 */
public class OMAuthenticationManager {

    private Context context;
    private static OMAuthenticationManager instance = null;

    private Map<AuthenticatorInstanceKey, AuthenticatorInfo> registeredAuthenticators = new HashMap<>();
    private Map<AuthenticatorInstanceKey, OMAuthenticator> authenticatorInstances = new HashMap<>();

    /**
     * This is a singleton.
     */
    private OMAuthenticationManager(Context context) {
        this.context = context;
    }

    /**
     * Singleton instance of the <code>OMAuthenticationManager</code>. All the registered
     * <code>OMAuthenticator</code> instances will get a reference of OMAuthenticationPolicy
     * instance passed here.
     * @param context context must not be null
     * @return singleton instance of OMAuthenticationManager
     * @throws OMAuthenticationManagerException
     */
    public static OMAuthenticationManager getInstance(Context context)
            throws OMAuthenticationManagerException {

        if (context == null) {
            throw new NullPointerException("context");
        }

        if (instance != null) {
            return instance;
        }

        instance = new OMAuthenticationManager(context);
        Map<AuthenticatorInstanceKey, AuthenticatorInfo> map = deserializeAuthenticationManagerState(context);
        instance.registeredAuthenticators.putAll(map);
        map.clear();

        return instance;
    }

    /**
     * This function will be used to register authenticator plugin to SDK.
     * @param authenticatorName
     * @param className
     * @return
     * @throws NullPointerException
     * @throws OMAuthenticationManagerException
     */
    public boolean registerAuthenticator(String authenticatorName, String className)
            throws NullPointerException, OMAuthenticationManagerException {

        try {
            Class c = Class.forName(className);
            if (!OMAuthenticator.class.isAssignableFrom(c)) {
                throw new OMAuthenticationManagerException(OMErrorCode.INVALID_INPUT,
                        "Class [" + className + "] must implement OMAuthenticator interface");
            }
            return registerAuthenticator(authenticatorName, c);
        } catch (ClassNotFoundException e) {
            throw new OMAuthenticationManagerException(OMErrorCode.INVALID_INPUT, e);
        }
    }

    /**
     * This function will be used to register authenticator plugin to SDK.
     * Client implements authenticator plugin then client uses this API to register plugin.
     * It will register plugin in SDK and persist that information.
     * @param authenticatorName
     * @param c
     * @return
     */
    public <T extends OMAuthenticator> boolean registerAuthenticator(String authenticatorName, Class<T> c)
            throws NullPointerException, OMAuthenticationManagerException {

        if (TextUtils.isEmpty(authenticatorName)) {
            throw new NullPointerException("authenticatorName cannot be null");
        }

        if (c == null) {
            throw new NullPointerException("class cannot be null");
        }

        if (registeredAuthenticators.containsKey(new AuthenticatorInstanceKey(authenticatorName))) {
            throw new OMAuthenticationManagerException(OMErrorCode.INVALID_INPUT,
                    "An authenticator with id [" + authenticatorName + "] already exists.");
        }

        String existingNameForType = getAuthenticatorNameForType(c);
        if (existingNameForType != null) {
            throw new OMAuthenticationManagerException(OMErrorCode.INVALID_INPUT,
                    "An authenticator with class [" + c.getName() + "] already exists.");
        }


        try {
            AuthenticatorInfo ai = new AuthenticatorInfo(authenticatorName, c.getName());
            registeredAuthenticators.put(new AuthenticatorInstanceKey(authenticatorName), ai);
            serializeAuthenticationManagerState(context, registeredAuthenticators);
            return true;
        } catch (Exception e) {
            throw new OMAuthenticationManagerException(OMErrorCode.INTERNAL_ERROR, e.getMessage(), e);
        }
    }

    /**
     * Removes authenticator registered under the given id.
     * @param authenticatorName
     * @return
     */
    public boolean unregisterAuthenticator(String authenticatorName)
            throws NullPointerException, OMAuthenticationManagerException {
        if (TextUtils.isEmpty(authenticatorName)) {
            throw new NullPointerException("authenticatorName");
        }

        if (isEnabled(authenticatorName)) {
            // Unregister can be done only if authenticator is disabled.
            throw new OMAuthenticationManagerException(OMErrorCode.DISABLE_AUTHENTICATOR_INSTANCE);
        }

        AuthenticatorInstanceKey aik = new AuthenticatorInstanceKey(authenticatorName);
        if (registeredAuthenticators.containsKey(aik)) {
            registeredAuthenticators.remove(aik);
            serializeAuthenticationManagerState(context, registeredAuthenticators);
        }

        return true;
    }

    /**
     * Unregister authenticator of given type.
     * @param type
     * @param <T>
     * @return
     * @throws OMAuthenticationManagerException
     */
    public <T extends OMAuthenticator> boolean unregisterAuthenticator(Class<T> type)
            throws OMAuthenticationManagerException {
        Set<AuthenticatorInstanceKey> keysToBeRemoved = new HashSet<>();
        Set<Map.Entry<AuthenticatorInstanceKey, AuthenticatorInfo>> entries = this.registeredAuthenticators.entrySet();
        for (Map.Entry<AuthenticatorInstanceKey, AuthenticatorInfo> entry : entries ) {
            if (entry.getValue().className.equals(type.getName())) {
                keysToBeRemoved.add(entry.getKey());
            }
        }

        for (AuthenticatorInstanceKey key : keysToBeRemoved) {
            registeredAuthenticators.remove(key);
        }
        serializeAuthenticationManagerState(context, registeredAuthenticators);
        return true;
    }


    /**
     * Return currently enabled authenticator instance.
     * @param authenticatorName
     * @return
     * @throws OMAuthenticationManagerException if authenticator is unknown
     */
    public OMAuthenticator getAuthenticator(String authenticatorName) throws OMAuthenticationManagerException {
        return getAuthenticator(new AuthenticatorInstanceKey(authenticatorName));
    }

    /**
     * Authenticator of given type.
     * @param type
     * @param <T>
     * @return
     * @throws OMAuthenticationManagerException if there is no authenticator of given type
     */
    public <T extends OMAuthenticator> OMAuthenticator getAuthenticator(Class<T> type)
            throws OMAuthenticationManagerException {
        String authenticatorName = getAuthenticatorNameForType(type);

        if (authenticatorName == null) {
            throw new OMAuthenticationManagerException(OMErrorCode.INVALID_INPUT,
                    "No registered authenticator of type " + type.getName());
        }

        return getAuthenticator(authenticatorName);
    }

    /**
     * Authenticator name of a given type, or null if one hasn't been registered.
     * @param type
     * @param <T>
     * @return
     * @throws OMAuthenticationManagerException
     */
    private <T extends OMAuthenticator> String getAuthenticatorNameForType(Class<T> type)
            throws OMAuthenticationManagerException {
        Set<Map.Entry<AuthenticatorInstanceKey, AuthenticatorInfo>> entries = this.registeredAuthenticators.entrySet();
        for (Map.Entry<AuthenticatorInstanceKey, AuthenticatorInfo> entry : entries ) {
            if (entry.getValue().className.equals(type.getName())) {
                return entry.getKey().authenticatorName;
            }
        }
        return null;
    }

    /**
     * Authenticator of a given type and instance id.
     * @param type
     * @param instanceId
     * @param <T>
     * @return
     * @throws OMAuthenticationManagerException for unknown authenticator
     */
    public <T extends OMAuthenticator> OMAuthenticator getAuthenticator(Class<T> type, String instanceId)
            throws OMAuthenticationManagerException {
        String authenticatorName = getAuthenticatorNameForType(type);

        if (authenticatorName == null) {
            throw new OMAuthenticationManagerException(OMErrorCode.INVALID_INPUT,
                    "No registered authenticator of type " + type.getName());
        }

        return getAuthenticator(authenticatorName, instanceId);
    }

    /**
     * Authenticator with authenticator name and instance id.
     * @param authenticatorName
     * @param instanceId
     * @return
     * @throws OMAuthenticationManagerException for unknown authenticator
     */
    public OMAuthenticator getAuthenticator(String authenticatorName, String instanceId)
            throws OMAuthenticationManagerException{
        AuthenticatorInstanceKey aik = new AuthenticatorInstanceKey(authenticatorName, instanceId);
        return getAuthenticator(aik);
    }


    private OMAuthenticator getAuthenticator(AuthenticatorInstanceKey aik) throws OMAuthenticationManagerException {
        AuthenticatorInfo ai = registeredAuthenticators.get(aik);
        if (ai == null) {
            throw new OMAuthenticationManagerException(OMErrorCode.INVALID_INPUT, "Unknown authenticator: " + aik);
        }

        if (!ai.isEnabled()) {
            throw new OMAuthenticationManagerException(OMErrorCode.INVALID_INPUT, "Disabled authenticator: " + aik);
        }

        OMAuthenticator authenticator = authenticatorInstances.get(aik);
        if (authenticator != null) {
            return authenticator;
        }

        try {
            authenticator = newAuthenticatorInstanceByKey(aik);
            authenticatorInstances.put(aik, authenticator);
            return authenticator;
        } catch (Exception e) {
            throw new OMAuthenticationManagerException(OMErrorCode.INTERNAL_ERROR, e.getMessage(), e);
        }
    }

    private OMAuthenticator newAuthenticatorInstanceByKey(AuthenticatorInstanceKey aik)
            throws InstantiationException, IllegalAccessException, ClassNotFoundException {
        AuthenticatorInfo info = registeredAuthenticators.get(aik);
        OMAuthenticator authenticator = newAuthenticatorInstanceByClassName(info.className);
        return authenticator;
    }

    private OMAuthenticator newAuthenticatorInstanceByClassName(String className)
            throws ClassNotFoundException, InstantiationException, IllegalAccessException {
        return newAuthenticatorInstanceByType(Class.forName(className));
    }

    private OMAuthenticator newAuthenticatorInstanceByType(Class type)
            throws IllegalAccessException, InstantiationException {
        return (OMAuthenticator) type.newInstance();
    }


    /**
     * It will tell if local authentication is enabled or not. Returns true if enabled else false.
     * @param authenticatorName
     * @return
     */
    public boolean isEnabled(String authenticatorName) {
        return isEnabled(new AuthenticatorInstanceKey(authenticatorName));
    }

    /**
     * If the given authenticator name and instance id is enabled.
     * @param authenticatorName
     * @param instanceId
     * @return
     */
    public boolean isEnabled(String authenticatorName, String instanceId) {
        return isEnabled(new AuthenticatorInstanceKey(authenticatorName, instanceId));
    }


    private boolean isEnabled(AuthenticatorInstanceKey aik) {
        AuthenticatorInfo ai = registeredAuthenticators.get(aik);
        return ai != null && ai.isEnabled();
    }

    /**
     * Enables authenticator with the given name. See {@link OMAuthenticationManager#registerAuthenticator(String, String)}
     * and it's overloaded version on how to register a given {@link OMAuthenticator} instance with this manager.
     * <br/>
     *
     * If we already have an authenticator registered under the given name, a exception will be thrown.
     *
     * @param authenticatorName
     * @throws OMAuthenticationManagerException if authenticator is unknown
     */
    public void enableAuthentication(String authenticatorName) throws OMAuthenticationManagerException {
        enableAuthentication(new AuthenticatorInstanceKey(authenticatorName));
    }

    /**
     * Enables a
     * @param authenticatorName
     * @param instanceId
     * @throws OMAuthenticationManagerException if authenticator is unknown
     */
    public void enableAuthentication(String authenticatorName, String instanceId) throws OMAuthenticationManagerException {
        enableAuthentication(new AuthenticatorInstanceKey(authenticatorName, instanceId));
    }

    /**
     * Actual heavy lifting for enabling an authenticator.
     * @param aik
     */
    private void enableAuthentication(AuthenticatorInstanceKey aik) throws OMAuthenticationManagerException {

        // look for both authenticator name and instance id...
        AuthenticatorInfo ai = registeredAuthenticators.get(aik);

        if (ai == null) {
            // authenticator name, instance id combo failed, now we must have a authenticator with the name
            ai = registeredAuthenticators.get(new AuthenticatorInstanceKey(aik.getAuthenticatorName()));
            if (ai == null) {
                throw new OMAuthenticationManagerException(OMErrorCode.INVALID_INPUT,
                        "Unknown authenticator " + aik);
            }

            // now, we want to register this new combo of authenticator name and instance id...
            registeredAuthenticators.put(aik, new AuthenticatorInfo(ai.getAuthenticatorName(), ai.className));
            ai = registeredAuthenticators.get(aik);
        }

        ai.setEnabled(true);
        serializeAuthenticationManagerState(context, registeredAuthenticators);
    }

    private void checkForDuplicateAuthenticator(AuthenticatorInstanceKey aik) throws OMAuthenticationManagerException {
        if (registeredAuthenticators.containsKey(aik)) {
            throw new OMAuthenticationManagerException(OMErrorCode.INVALID_STATE,
                    "There is an existing authenticator registered under the given name: [" + aik.getAuthenticatorName() + "]");
        }
    }

    /**
     * Disables the 'singleton' authenticator under the given name.
     * @param authenticatorName
     */
    public void disableAuthentication(String authenticatorName) throws OMAuthenticationManagerException {
        disableAuthentication(new AuthenticatorInstanceKey(authenticatorName));
    }

    public void disableAuthentication(String authenticatorName, String instanceId) throws OMAuthenticationManagerException {
        disableAuthentication(new AuthenticatorInstanceKey(authenticatorName, instanceId));
    }

    private void disableAuthentication(AuthenticatorInstanceKey aik) throws OMAuthenticationManagerException {
        AuthenticatorInfo ai = registeredAuthenticators.get(aik);
        if (ai == null) {
            throw new OMAuthenticationManagerException(OMErrorCode.INVALID_INPUT,
                    "Unknown authenticator " + aik);
        }
        ai.setEnabled(false);
        authenticatorInstances.remove(aik);
        serializeAuthenticationManagerState(context, registeredAuthenticators);
    }


    /**
     * Changes authentication type from currently used to authentication type passed as parameter.
     * @param currentAuthenticatorName
     * @param newAuthenticatorName
     */
    public void changeAuthenticationType(String currentAuthenticatorName, String newAuthenticatorName) throws OMAuthenticationManagerException {
        AuthenticatorInstanceKey currentAIK = new AuthenticatorInstanceKey(currentAuthenticatorName);
        AuthenticatorInstanceKey newAIK = new AuthenticatorInstanceKey(newAuthenticatorName);
        changeAuthenticationType(currentAIK, newAIK);
    }

    /**
     * Changes authentication type from the authenticator given by
     * (currentAuthenticatorName, currentInstanceId) to authenticator identified by newAuthenticatorName.
     * @param currentAuthenticatorName
     * @param currentInstanceId
     */
    public void changeAuthenticationType(String currentAuthenticatorName, String currentInstanceId,
                                         String newAuthenticatorName) throws OMAuthenticationManagerException {
        AuthenticatorInstanceKey currentAIK = new AuthenticatorInstanceKey(currentAuthenticatorName, currentInstanceId);
        AuthenticatorInstanceKey newAIK = new AuthenticatorInstanceKey(newAuthenticatorName);
        changeAuthenticationType(currentAIK, newAIK);

    }

    /**
     * Changes authentication type from the authenticator given by
     * (currentAuthenticatorName, currentInstanceId) to authenticator identified by
     * (newAuthenticatorName, newInstanceId) parameter tuple.
     * @param currentAuthenticatorName
     * @param currentInstanceId
     * @param newAuthenticatorName
     * @param newInstanceId
     */
    public void changeAuthenticationType(String currentAuthenticatorName, String currentInstanceId,
                                         String newAuthenticatorName, String newInstanceId) throws OMAuthenticationManagerException {
        AuthenticatorInstanceKey currentAIK = new AuthenticatorInstanceKey(currentAuthenticatorName, currentInstanceId);
        AuthenticatorInstanceKey newAIK = new AuthenticatorInstanceKey(newAuthenticatorName, newInstanceId);
        changeAuthenticationType(currentAIK, newAIK);

    }

    /**
     * Internal logic to handle change of authenticator.
     * @param currentAIK
     * @param newAIK
     */
    private void changeAuthenticationType(AuthenticatorInstanceKey currentAIK, AuthenticatorInstanceKey newAIK) throws OMAuthenticationManagerException {
        AuthenticatorInfo ai = registeredAuthenticators.get(currentAIK);
        if (ai == null) {
            throw new OMAuthenticationManagerException(OMErrorCode.INVALID_INPUT,
                    "Unknown authenticator " + currentAIK);
        }

        ai = registeredAuthenticators.get(newAIK);
        if (ai == null) {
            throw new OMAuthenticationManagerException(OMErrorCode.INVALID_INPUT,
                    "Unknown authenticator " + newAIK);
        }

        disableAuthentication(currentAIK);
        enableAuthentication(newAIK);
    }

    /**
     * Persists the current state.
     */
    private static void serializeAuthenticationManagerState(Context context, Map<AuthenticatorInstanceKey, AuthenticatorInfo> data)
            throws OMAuthenticationManagerException {
        File outputFile = getDataFile(context);

        FileOutputStream fos;
        ObjectOutputStream oos = null;

        try {
            fos = new FileOutputStream(outputFile);
            oos = new ObjectOutputStream(fos);
            oos.writeObject(data);
        } catch (Exception e) {
            throw new OMAuthenticationManagerException(OMErrorCode.INTERNAL_ERROR, e);
        } finally {
            closeQuietly(oos);
        }
    }

    /**
     * Reads persisted state.
     */
    private static Map<AuthenticatorInstanceKey, AuthenticatorInfo> deserializeAuthenticationManagerState(Context context)
            throws OMAuthenticationManagerException {
        File inputFile = getDataFile(context);

        if (!inputFile.exists()) {
            return new HashMap<>();
        }

        FileInputStream fis;
        ObjectInputStream ois = null;

        try {
            fis = new FileInputStream(inputFile);
            ois = new ObjectInputStream(fis);
            Object o = ois.readObject();
            return (Map<AuthenticatorInstanceKey, AuthenticatorInfo>) o;
        } catch (Exception e) {
            throw new OMAuthenticationManagerException(OMErrorCode.INTERNAL_ERROR, e);
        } finally {
            closeQuietly(ois);
        }

    }


    /**
     * Just close it!
     * @param closeable
     */
    private static void closeQuietly(Closeable closeable) {
        if (closeable != null) {
            try {
                closeable.close();
            } catch (IOException ignored) {}
        }

    }
    /**
     * File for our persisted state.
     *
     * @return
     */
    private static File getDataFile(Context context) {
        String filePath = context.getFilesDir() + File.pathSeparator
                + "authentication_manager_data.bin";

        File file = new File(filePath);
        return file;
    }

    /**
     * Info holder for our authenticators.
     */
    static class AuthenticatorInfo implements Serializable {

        private static final long serialVersionUID = 229374385213198493L;

        private String authenticatorName;
        private String className;
        boolean enabled;

        public AuthenticatorInfo() {
        }

        public AuthenticatorInfo(String authenticatorName, String className) {
            this.authenticatorName = authenticatorName;
            this.className = className;
        }

        public String getAuthenticatorName() {
            return authenticatorName;
        }

        public String getClassName() {
            return className;
        }

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }
    }

    /**
     * A tuple of authenticator id and it's instance id to uniquely identify
     * an instance of an authenticator.
     */
    static class AuthenticatorInstanceKey implements Serializable {
        private static final long serialVersionUID = 5891703175339926840L;

        private String authenticatorName;
        private String instanceId;

        /**
         * Same instance id as the authenticator id
         * @param authenticatorName
         */
        public AuthenticatorInstanceKey(String authenticatorName) {
            this(authenticatorName, authenticatorName);
        }
        public AuthenticatorInstanceKey(String authenticatorName, String instanceId) {
            this.authenticatorName = authenticatorName;
            this.instanceId = instanceId;
        }

        public String getAuthenticatorName() {
            return authenticatorName;
        }

        public String getInstanceId() {
            return instanceId;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;

            AuthenticatorInstanceKey that = (AuthenticatorInstanceKey) o;

            if (authenticatorName != null ? !authenticatorName.equals(that.authenticatorName) : that.authenticatorName != null)
                return false;
            return instanceId != null ? instanceId.equals(that.instanceId) : that.instanceId == null;

        }

        @Override
        public int hashCode() {
            int result = authenticatorName != null ? authenticatorName.hashCode() : 0;
            result = 31 * result + (instanceId != null ? instanceId.hashCode() : 0);
            return result;
        }

        @Override
        public String toString() {
            String s = "{authenticatorName='" + authenticatorName + '\'';
            if (!authenticatorName.equals(instanceId)) {
                s += ", instanceId='" + instanceId + '\'';
            }
            s += '}';
            return s;
        }
    }
}
