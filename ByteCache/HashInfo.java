package ByteCache;

import java.io.BufferedWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Iterator;
import java.util.Set;

/**
 * Created by Sudhir_Kumar on 5/9/2017.
 */
public class HashInfo {
    class TypeTimeCount {
        long accessTime;
        int count;
        String contentType;

        public TypeTimeCount() {
            accessTime = 0;
            count = 0;
            contentType = "";
        }
        public void incrementCount() {
            count++;
        }
        public int getCount() {
            return count;
        }
        public long getAccessTime() {
            return accessTime;
        }
        public void setAccessTime(long timeStamp) {
            accessTime = timeStamp;
        }
        public String getContentType() {
            return contentType;
        }
        public void setContentType(String ctype) {
            contentType = ctype;
        }
    }

    public HashMap<String, TypeTimeCount>   hashInfo;
    public HashInfo() {
        hashInfo = new HashMap<String, TypeTimeCount>();
    }
    public void insertHash(String hash, String ctype) {
        TypeTimeCount   ttc = hashInfo.get(hash);
        if (ttc == null) {
            ttc = new TypeTimeCount();
            hashInfo.put(hash, ttc);
        } else {
            ttc.incrementCount();
        }
        ttc.setContentType(ctype);
    }

    public void show(BufferedWriter outf) throws IOException {
        Set set = hashInfo.entrySet();
        Iterator i = set.iterator();
        int count=0;
        int numHashes = 0;
        int matchedHashes = 0;
        int unMatchedHashes = 0;
        while (i.hasNext()) {
            Map.Entry me = (Map.Entry) i.next();
            TypeTimeCount ttc = (TypeTimeCount) me.getValue();
            numHashes++;
            count = ttc.getCount();
            outf.write("\t" + me.getKey() + " : " + ttc.getContentType() + " : " + ttc.getCount() + "\n");
            if (count > 0) {
                matchedHashes++;
                System.out.println("\t" + me.getKey() + " : " + ttc.getContentType() + " : " + ttc.getCount() + "\n");
            } else {
                unMatchedHashes++;
            }
        }
        outf.write("\t Number of hashes: " + numHashes + ", Matched:"+matchedHashes+ ", Unmatched:"+ unMatchedHashes+"\n");
        System.out.println("\t Number of hashes: " + numHashes + ", Matched:"+matchedHashes+ ", Unmatched:"+ unMatchedHashes);

    }
}
