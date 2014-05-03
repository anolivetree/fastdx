package com.android.dx.command;

import com.android.dex.util.FileUtils;
import com.android.dx.command.dexer.Main;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class DexCache {

    static public final String CACHE_DIR = System.getProperty("user.home") + File.separatorChar + ".dxcache";
    static public final String LOCK_FILE = CACHE_DIR + "/lock"; // TODO not used yet
    static final int MAX_CACHE_ENTRIES = 3000;

    static private DexCache instance;

    public synchronized static DexCache getInstance() {
        if (instance == null) {
            instance = new DexCache();
        }
        return instance;
    }

    private MessageDigest digest;

    private DexCache() {
        try {
            digest = MessageDigest.getInstance("SHA-1");
            ensureCacheDir();
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError();
        }
    }

    public byte[] getDex(byte[] classFile) {
        String name = "c2d-" + hash(classFile);

        File file = new File(CACHE_DIR, name);
        if (file.exists() && file.isFile()) {
            try {
                byte[] dex;
                dex = FileUtils.readFile(file);
                return dex;
            } catch (Exception e) {
                DxConsole.out.println("cannot read cache file. ignore " + e);
                return null;
            }
        }
        return null;
    }

    public void putDex(byte[] classFile, byte[] dex) {
        String name = "c2d-" + hash(classFile);

        File file = new File(CACHE_DIR, name);
        FileOutputStream fout = null;
        try {
            fout = new FileOutputStream(file);
            fout.write(dex);
            fout.close();
        } catch (FileNotFoundException e) {
            DxConsole.out.println("c2d cache write failed " + e);
            file.delete();
        } catch (IOException e) {
            DxConsole.out.println("c2d cache write failed " + e);
            file.delete();
        }
    }

    public void trim() {
        File dir = new File(CACHE_DIR);
        if (!dir.exists() || !dir.isDirectory()) {
            DxConsole.out.println("dir not exist or not a directory.");
            return;
        }

        File[] files = dir.listFiles(new FileFilter() {
            @Override
            public boolean accept(File pathname) {
                if (pathname.getName().startsWith("c2d-")) {
                    return true;
                }
                return false;
            }
        });

        if (files.length <= MAX_CACHE_ENTRIES) {
            return;
        }

        Arrays.sort(files, new Comparator<File>() {
            @Override
            public int compare(File o1, File o2) {
                // new one comes first
                long t1 = o1.lastModified();
                long t2 = o2.lastModified();
                if (t1 < t2) {
                    return 1;
                }
                if (t1 > t2) {
                    return -1;
                }
                return 0;
            }
        });

        for (int i = MAX_CACHE_ENTRIES; i < files.length; i++) {
            DxConsole.out.println("deleting c2d cache. lastModified=" +files[i].lastModified());
            files[i].delete();
        }

    }

    private void ensureCacheDir() {
        File dir = new File(CACHE_DIR);
        if (!dir.exists()) {
            DxConsole.out.println("cache dir doesn't exist. create.");
            dir.mkdirs();
        }

    }

    static private char[] table;

    static {
        table = new char[16];
        table[0] = '0';
        table[1] = '1';
        table[2] = '2';
        table[3] = '3';
        table[4] = '4';
        table[5] = '5';
        table[6] = '6';
        table[7] = '7';
        table[8] = '8';
        table[9] = '9';
        table[10] = 'a';
        table[11] = 'b';
        table[12] = 'c';
        table[13] = 'd';
        table[14] = 'e';
        table[15] = 'f';
    }


    static public String hex(byte[] data) {
        char[] chars = new char[data.length * 2];

        for (int i = 0; i < data.length; i++) {
            chars[i * 2] = table[(data[i] >> 4) & 0xf];
            chars[i * 2 + 1] = table[data[i]& 0xf];
        }

        return new String(chars);
    }

    public String hash(byte[] data) {
        digest.reset();
        byte[] d = digest.digest(data);
        return hex(d);
    }



}
