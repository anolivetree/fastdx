package com.android.dx.merge;

import com.android.dex.util.FileUtils;
import com.android.dx.command.DxConsole;
import com.android.dx.command.dexer.Main;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class MergeCache {

    static public final String CACHE_DIR = System.getProperty("user.home") + File.separatorChar + ".dxcache";
    static public final String LOCK_FILE = CACHE_DIR + "/lock"; // TODO not used yet
    static public final String INDEX_FILE = CACHE_DIR + "/index";
    static final int MAX_CACHE_ENTRIES = 100;

    static private MergeCache instance;

    static private class CacheEntry {
        final String mergeSource;
        final String fileName;
        final String fileHash;

        private CacheEntry(String mergeSource, String fileName, String fileHash) {
            this.mergeSource = mergeSource;
            this.fileName = fileName;
            this.fileHash = fileHash;
        }
    }


    public synchronized static MergeCache getInstance() {
        if (instance == null) {
            instance = new MergeCache();
        }
        return instance;
    }

    private MessageDigest digest;
    private ArrayList<CacheEntry> cacheEntries = new ArrayList<CacheEntry>();

    private MergeCache() {
        try {
            digest = MessageDigest.getInstance("SHA-1");
            loadCacheIndex();
            ensureCacheDir();
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError();
        }
    }

    private void loadCacheIndex() {
        cacheEntries.clear();
        try {
            BufferedReader r = new BufferedReader(new FileReader(new File(INDEX_FILE)));
            while (true) {
                String line = r.readLine();
                if (line == null) {
                    break;
                }
                int pos = line.indexOf(' ');
                if (pos == -1) {
                    DxConsole.out.println("invalid cache format. no merge source" + line);
                    continue;
                }
                String mergeSource = line.substring(0, pos);
                if (mergeSource.length() == 0 || (mergeSource.length() % 40) != 0) {
                    DxConsole.out.println("invalid cache mergeSource. " + line);
                    continue;
                }

                line = line.substring(pos + 1);

                pos = line.indexOf(' ');
                if (pos == -1) {
                    DxConsole.out.println("invalid cache format. no file hash" + line);
                    continue;
                }
                String fileHash = line.substring(0, pos);
                if (fileHash.length() != 40) {
                    DxConsole.out.println("invalid cache file hash. " + line);
                    continue;
                }

                String fileName = line.substring(pos + 1);
                File file = new File(CACHE_DIR, fileName);
                if (!file.exists() || !file.isFile()) {
                    DxConsole.out.println("invalid cache file doesn't exist. " + line);
                    continue;
                }

                cacheEntries.add(new CacheEntry(mergeSource, fileName, fileHash));
            }
        } catch (FileNotFoundException e) {
            DxConsole.out.println("cache load failed. " + e);
        } catch (IOException e) {
            DxConsole.out.println("cache load failed. " + e);
        }

        /*
        Collections.sort(cacheEntries, new Comparator<CacheEntry>() {
            @Override
            public int compare(CacheEntry o1, CacheEntry o2) {
                // longer source comes first
                return o2.mergeSource.length() - o1.mergeSource.length();
            }
        });
        */
    }

    public void saveCacheIndex() {
        // trim cache
        while (cacheEntries.size() > MAX_CACHE_ENTRIES) {
            CacheEntry entry = cacheEntries.remove(MAX_CACHE_ENTRIES);
            File file = new File(CACHE_DIR, entry.fileName);
            file.delete();
            DxConsole.out.println("cache deleted. file=" + file.getName());
        }


        File file = new File(INDEX_FILE);
        BufferedWriter fout = null;
        try {
            fout = new BufferedWriter(new FileWriter(file));
            for (CacheEntry entry : cacheEntries) {
                fout.write(entry.mergeSource);
                fout.write(' ');
                fout.write(entry.fileHash);
                fout.write(' ');
                fout.write(entry.fileName);
                fout.newLine();
            }
            fout.close();
        } catch (IOException e) {
            DxConsole.out.println("cannot write cache index. " + e);
        }
    }

    /**
     * returned info has hashStr set.
     * @param outArray
     * @param dexBuffers
     * @return
     */
    public List<Main.LibraryDexInfo> reorder(byte[] outArray, List<Main.LibraryDexInfo> dexBuffers) {

        HashMap<String, Main.LibraryDexInfo> map = new HashMap<String, Main.LibraryDexInfo>();

        for (Main.LibraryDexInfo info : dexBuffers) {
            digest.reset();
            byte[] d = digest.digest(info.data);
            map.put(hex(d), new Main.LibraryDexInfo(info.data, info.timestamp, hex(d)));
        }

        if (outArray != null) {
            digest.reset();
            byte[] d = digest.digest(outArray);
            //map.put(hex(d), new Main.LibraryDexInfo(outArray, new Date().getTime(), hex(d)));
            map.put(hex(d), new Main.LibraryDexInfo(outArray, 1, hex(d)));
        }

        ArrayList<Main.LibraryDexInfo> orderdList = new ArrayList<Main.LibraryDexInfo>();

        // find the cache with the longest mergeSource
        for (int i = 0; i < cacheEntries.size(); i++) {
            String name = cacheEntries.get(i).mergeSource;
            int num = name.length() / 40;
            boolean match = true;
            for (int n = 0; n < num; n++) {
                String sub = name.substring(n * 40, (n + 1) * 40);
                if (!map.containsKey(sub)) {
                    match = false;
                    break;
                }
            }
            if (match) {

                DxConsole.out.println("found a matching cache. mergeSource=" + name);

                // check file hash
                byte[] data = null;
                try {
                    data = FileUtils.readFile(new File(CACHE_DIR, cacheEntries.get(i).fileName));
                } catch (Exception e) {
                    DxConsole.out.println("cannot read cache file. ignore " + e);
                    continue;
                }
                if (data == null) {
                    DxConsole.out.println("cannot read cache file. ignore");
                    continue;
                }
                String hash = hash(data);
                if (!cacheEntries.get(i).fileHash.equals(hash)) {
                    DxConsole.out.println("file hash doesn't match. ignore");
                    continue;
                }

                // remove matching dexes from map
                for (int n = 0; n < num; n++) {
                    String sub = name.substring(n * 40, (n + 1) * 40);
                    if (map.remove(sub) == null) {
                        throw new RuntimeException("no map entry??");
                    }
                }
                orderdList.add(new Main.LibraryDexInfo(
                        data,
                        0,//must be first when sorted
                        name));

                // move the matched entry to head
                CacheEntry entry = cacheEntries.get(i);
                cacheEntries.remove(i);
                cacheEntries.add(0, entry);
                break;
            }
        }

        // sort the entry left in map by timestamp
        for (Main.LibraryDexInfo info : map.values()) {
            orderdList.add(info);
        }
        Collections.sort(orderdList, new Comparator<Main.LibraryDexInfo>() {
            @Override
            public int compare(Main.LibraryDexInfo o1, Main.LibraryDexInfo o2) {
                if (o1.timestamp < o2.timestamp) {
                    return -1;
                }
                if (o1.timestamp > o2.timestamp) {
                    return 1;
                }
                return 0;
            }
        });

        return orderdList;
    }

    public void add(String mergeSource, byte[] data) {
        // add the new entry to head

        for (int i = 0; i < cacheEntries.size(); i++) {
            CacheEntry entry = cacheEntries.get(i);
            if (entry.mergeSource.equals(mergeSource)) {
                DxConsole.out.println("move cache entry to head. mergeSource=" + mergeSource);
                cacheEntries.remove(i);
                cacheEntries.add(0, entry);
                return;
            }
        }

        File file;
        try {
            file = File.createTempFile("mergecache-", "", new File(CACHE_DIR));
            FileOutputStream fout = new FileOutputStream(file);
            fout.write(data);
            fout.close();
        } catch (IOException e) {
            DxConsole.out.println("cannot create cache file " + e);
            return;
        }

        CacheEntry entry = new CacheEntry(mergeSource, file.getName(), hash(data));
        cacheEntries.add(0, entry);

        DxConsole.out.println("cache entry added. mergeSource=" + mergeSource);
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
