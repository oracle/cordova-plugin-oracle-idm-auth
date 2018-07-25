#
# Copyright (c) 2017, Oracle and/or its affiliates.
# The Universal Permissive License (UPL), Version 1.0
#
# Add project specific ProGuard rules here.
# By default, the flags in this file are appended to flags specified
# in D:\Android_SDK/tools/proguard/proguard-android.txt
# You can edit the include path and order by changing the proguardFiles
# directive in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# Add any project specific keep options here:

# If your project uses WebView with JS, uncomment the following
# and specify the fully qualified class name to the JavaScript interface
# class:
-keepclassmembers,includedescriptorclasses class oracle.idm.mobile.auth.webview.FederatedWebViewHandler$FederatedJavascriptInterface {
   public *;
}

-keepnames class * implements oracle.idm.mobile.auth.local.OMAuthenticator
-keepnames class * implements java.io.Serializable

-keepclassmembers class * implements java.io.Serializable {
    static final long serialVersionUID;
    private static final java.io.ObjectStreamField[] serialPersistentFields;
    !static !transient <fields>;
    private void writeObject(java.io.ObjectOutputStream);
    private void readObject(java.io.ObjectInputStream);
    java.lang.Object writeReplace();
    java.lang.Object readResolve();
}

-keep class org.slf4j.** { *; }
-dontwarn org.slf4j.**
-dontwarn com.nimbusds.**

#BEGIN: OkHttp uses reflection to obtain the following classes. So, switching off the notes.
-dontnote com.android.org.conscrypt.SSLParametersImpl
-dontnote org.apache.harmony.xnet.provider.jsse.SSLParametersImpl
-dontnote dalvik.system.CloseGuard
-dontnote sun.security.ssl.SSLContextImpl
-dontwarn okhttp3.**
-dontwarn okio.**
#END: OkHttp

# Enable proguard with Cordova
-keep class org.apache.cordova.** { *; }
-keep public class * extends org.apache.cordova.CordovaPlugin
