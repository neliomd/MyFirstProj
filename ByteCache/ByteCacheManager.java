package ByteCache;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Map;
import java.util.HashMap;
import java.util.Iterator;

import java.net.URI;
import java.net.URISyntaxException;

/**
 * Created by Sudhir_Kumar on 5/10/2017.
 */

// Make it a Singleton
public class ByteCacheManager {
    private static ByteCacheManager instance = null;
    public static HashMap<String, DataToHashList>   urlToDataHash;
    public static HashMap<String, HashInfo>         domainToHashInfo;

    protected ByteCacheManager() {
        // prevent instantiation by others
    }
    public static ByteCacheManager getInstance() {
        if (instance == null) {
            instance = new ByteCacheManager();
            urlToDataHash = new HashMap<String, DataToHashList>();
            domainToHashInfo = new HashMap<String, HashInfo>();
        }
        return instance;
    }

    public String getDomainName(String url) throws URISyntaxException {
        URI     uri = new URI(url);
        String domain = uri.getHost();
        return domain.startsWith("www.")? domain.substring(4): domain;
    }

    public synchronized void insertURLHash(String domain, DataToHashList dthl, String contenttype) {
        // Earlier, the first parameter was URL.
        //String  domain;
        //try {
        //    domain = getDomainName(url);
        //} catch (Exception exc) {
        //    System.out.println("Invalid URL. Ignoring");
        //    return;
        //}

        HashInfo hi = domainToHashInfo.get(domain);
        if (hi == null) {
            hi = new HashInfo();
            domainToHashInfo.put(domain, hi);
        }
        // Now iterate through all the hashes and insert them in hi
        for (String md5hash : dthl.hashList) {
            hi.insertHash(md5hash, contenttype);
        }
    }

    public void show() {
        BufferedWriter bw = null;
        FileWriter fw = null;
        Iterator it = domainToHashInfo.entrySet().iterator();
        try {
            fw = new FileWriter("myout.txt");
            bw = new BufferedWriter(fw);
        } catch (Exception exc) {
            exc.printStackTrace();
        }
        try {
            while (it.hasNext()) {
                Map.Entry me = (Map.Entry) it.next();
                String domain = (String) me.getKey();
                HashInfo hi = (HashInfo) me.getValue();
                System.out.println(domain + ":");
                bw.write(domain + ":\n");
                hi.show(bw);
            }
        } catch (IOException exc) {
            exc.printStackTrace();
        }
        try {
            if (bw != null) {
                bw.close();
            }
            if (fw != null) {
                fw.close();
            }
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }
}