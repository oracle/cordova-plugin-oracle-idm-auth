/*
 * Copyright (c) 2017, Oracle and/or its affiliates.
 * The Universal Permissive License (UPL), Version 1.0
 */


package oracle.idm.mobile.util;


import android.content.Context;
import android.content.Intent;
import android.content.pm.ResolveInfo;
import android.os.AsyncTask;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

/**
 * Main class to check for rooted devices.
 */
public class DeviceUtil {

    /**
     * True if device is rooted.
     *
     * @param context
     * @return
     */
    public static boolean isDeviceRooted(Context context) {
        boolean rooted = new DeviceUtil().checkForRoot();
        if (!rooted) {
            rooted = new BlackListedPackages().p1(context);
        }
        return rooted;
    }

    private boolean checkForRoot() {
        if (checkForSUPackages()) {
            return true;
        }
        if (checkForWhichCommand()) {
            return true;
        }

        if (checkForCommands()) {
            return true;
        }
        return false;
    }

    private boolean checkForSUPackages() {

        // /system/app/Superuser.apk
        char[] p1 = new char[]{'/', '@', '!', 's', '#', '1', 'y', '$', '%', 's', '*', '^',
                't', '%', '!', 'e', '!', '9', 'm', '6', '$', '/', '2', '!', 'a', '3', '^',
                'p', '&', '(', 'p', '%', '#', '/', '%', '!', 'S', '$', '#', 'u', '%', '4',
                'p', '#', '!', 'e', '&', '*', 'r', '#', '2', 'u', '#', '5', 's', '$', '^',
                'e', '%', '3', 'r', '#', ')', '.', '2', '#', 'a', '$', '*', 'p', '!', '@', 'k'};

        // /system/app/Supersu.apk
        char[] p2 = new char[]{'/', '$', '5', 's', '3', '%', 'y', '@', '4', 's', '^', '*',
                't', '2', ')', 'e', '4', '%', 'm', '#', '$', '/', ')', '(', 'a', '1', '$',
                'p', '!', '$', 'p', '%', ')', '/', '#', '!', 'S', '#', '$', 'u', '&', '@',
                'p', '%', '#', 'e', '$', '^', 'r', '*', '6', 's', '3', '^', 'u', '!', '#',
                '.', '+', '@', 'a', '_', '~', 'p', '#', '=', 'k'};

        File f1 = new File(getString(p1));
        if (f1.exists()) {
            return true;
        }

        File f2 = new File(getString(p2));
        if (f2.exists()) {
            return true;
        }

        return false;
    }

    private boolean checkForWhichCommand() {
        // /system/bin/which
        char[] c1 = new char[]{'/', '_', '#', 's', '+', '!', 'y', '$', '%', 's', '^', '5',
                't', '#', '1', 'e', '@', '*', 'm', '%', '$', '/', '+', '_', 'x', ')', '~',
                'b', '#', '%', 'i', '^', '&', 'n', '^', '$', '/', '~', '`', 'w', '^', '&',
                'h', '@', '^', 'i', '*', '=', 'c', '_', '$', 'h'};

        // su
        char[] c2 = new char[]{'s', 'v', 'r', 'u'};

        String[] s1 = new String[]{getString(c1), getString(c2)};

        if (new SystemExec().executeCommand(s1) != null) {
            return true;
        } else {
            return false;
        }
    }


    private boolean checkForCommands() {

        // test-keys
        char[] c1 = new char[]{'t', '+', '1', 'e', '@', '#', 's', '$', '-', 't', '$', '@',
                '-', '#', '!', 'k', '2', ')', 'e', '$', '(', 'y', '#', '7', 's'};

        // cat
        char[] c2 = new char[]{'c', '@', '(', 'a', '#', '3', 't'};

        // system/build.prop
        char[] c3 = new char[]{'s', '@', '#', 'y', '@', '*', 's', ')', '_', 't', '@', '~',
                'e', '$', '2', 'm', '!', '*', '/', '^', '+', 'b', '`', '-', 'u', '%', '0',
                'i', '&', '(', 'l', ')', '9', 'd', '$', '@', '.', '^', '#', 'p', '^', '3',
                'r', '9', '*', 'o', '!', '~', 'p'};

        // |
        char[] c4 = new char[]{'|'};

        // grep
        char[] c5 = new char[]{'g', '%', ',', 'r', '#', '@', 'e', '^', '@', 'p'};

        // ro.build.tags
        char[] c6 = new char[]{'r', '$', '#', 'o', '&', '!', '.', '#', '@', 'b', '_', '3',
                'u', '^', '$', 'i', '%', '&', 'l', '@', '~', 'd', '*', '9', '.', '*', '&',
                't', '^', '$', 'a', '&', '(', 'g', '#', '@', 's'};

        ArrayList<String> l = new SystemExec().executeCommand(new String[]{getString(c2), getString(c3), getString(c4), getString(c5), getString(c6)});
        if (l != null) {
            for (int i = 0; i < l.size(); i++) {
                if (l.get(i).contains(getString(c6)) && l.get(i).contains(getString(c1))) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Decodes our custom encoded strings.
     *
     * @param c
     * @return
     */
    public static String getString(char[] c) {
        StringBuilder s = new StringBuilder();
        for (int i = 0; i < c.length; i++) {
            if (i % 3 == 0) {
                s.append(c[i]);
            }

        }
        return s.toString();
    }

    // ---------------------------------------------------------------------------------------------
    private static class BlackListedPackages {

        private static List<char[]> list = new ArrayList<>();

        static {
            // com.amphoras.hidemyroot
            list.add(new char[]{'c', '#', '&', 'o', '!', '2', 'm', '^', ')', '.', '!', '@', 'a', '6', '%', 'm', '+', '=', 'p', '-', '0', 'h', '9', '&', 'o', '2', '%', 'r', '#', '4', 'a', '(', '7', 's', '(', '*', '.', '7', '5', 'h', '$', '6', 'i', '5', '&', 'd', '-', '_', 'e', ')', '*', 'm', '&', '#', 'y', '$', ')', 'r', '(', '!', 'o', '$', ')', 'o', '$', '^', 't'});

            // com.devadvance.rootcloakplus
            list.add(new char[]{'c', '-', '+', 'o', '8', '(', 'm', ')', '*', '.', '@', '#', 'd', '1', '%', 'e', '3', '@', 'v', '%', '4', 'a', '$', '%', 'd', '^', '&', 'v', '&', '*', 'a', '8', '(', 'n', '0', '_', 'c', '-', '=', 'e', '+', '_', '.', '(', '^', 'r', '&', '(', 'o', '&', '%', 'o', '$', '@', 't', '2', '@', 'c', '#', '7', 'l', '_', ')', 'o', '&', '6', 'a', '#', '$', 'k', '5', '7', 'p', '$', '%', 'l', '^', '8', 'u', '6', '&', 's'});

            // com.saurik.substrate
            list.add(new char[]{'c', '(', '0', 'o', '+', '#', 'm', '-', ')', '.', '8', '5', 's', '5', '4', 'a', '#', '@', 'u', '!', '*', 'r', '@', '$', 'i', '#', '@', 'k', '$', '5', '.', '+', '8', 's', '(', ')', 'u', '0', '`', 'b', '~', ')', 's', '(', '&', 't', '%', '#', 'r', '@', '#', 'a', '%', '6', 't', '8', ')', 'e'});

            // de.rob.android.xposed.installer
            list.add(new char[]{'d', '!', '@', 'e', '$', '^', '.', '(', '8', 'r', '2', '#', 'o', '(', '(', 'b', '*', '^', '.', '&', '^', 'a', '!', '@', 'n', '#', '$', 'd', '%', '5', 'r', '%', '6', 'o', '^', '*', 'i', '*', '(', 'd', '_', ')', '.', '*', '&', 'x', '#', '!', 'p', '0', '`', 'o', '~', '!', 's', '$', '4', 'e', '=', '_', 'd', '-', '+', '.', '5', '#', 'i', '(', '*', 'n', '&', '#', 's', '#', '$', 't', '^', '*', 'a', '&', '4', 'l', '^', '%', 'l', '#', '^', 'e', '%', '$', 'r'});
        }

        public boolean p1(Context context) {

            final Intent mainIntent = new Intent(Intent.ACTION_MAIN, null);
            mainIntent.addCategory(Intent.CATEGORY_LAUNCHER);
            final List<ResolveInfo> pkgAppsList = context.getPackageManager().queryIntentActivities(mainIntent, 0);
            for (int i = 0; i < pkgAppsList.size(); i++) {
                for (int j = 0; j < list.size(); j++) {
                    if (pkgAppsList.get(i).activityInfo.packageName.equals(DeviceUtil.getString(list.get(j)))) {
                        return true;
                    }
                }
            }
            return false;
        }
    }

    /**
     * The starting point for checking if a device is rooted. Calls all the
     * OS command in the background as well as checks the existence of
     * some rouge apps like rootcloakplus.
     */
    private static class DeviceUtilTask extends AsyncTask<Void, Void, Boolean> {

        private static String TAG = DeviceUtil.class.getSimpleName();
        private Context context;

        public DeviceUtilTask(Context context) {
            this.context = context;
        }

        @Override
        protected Boolean doInBackground(Void... voids) {
            boolean b = new DeviceUtil().checkForRoot();
            if (!b) {
                b = new BlackListedPackages().p1(context);
            }
            return b;
        }

        protected void onPostExecute(Boolean flag) {
            // device is rooted if flag == true
        }
    }

    //----------------------------------------------------------------------------------------------

    /**
     * Executes a command on underlying OS using Java's standard
     * {@link Runtime} interface.
     */
    private static class SystemExec {

        private static String TAG = SystemExec.class.getSimpleName();

        /**
         * Executes given command using {@link Runtime} and returns the output.
         *
         * @param s1
         * @return
         */
        public ArrayList<String> executeCommand(String[] s1) {

            Process localProcess;

            try {
                localProcess = Runtime.getRuntime().exec(s1);
            } catch (Exception e) {
                return null;
            }

            ArrayList<String> response = new ArrayList<>();
            BufferedReader in = new BufferedReader(new InputStreamReader(localProcess.getInputStream()));

            try {
                String line;
                while ((line = in.readLine()) != null) {
                    response.add(line);
                }
                in.close();
            } catch (Exception e) {
            }

            return response;
        }

    }

}
