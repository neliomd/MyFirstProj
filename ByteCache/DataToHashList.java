package ByteCache;

import javax.xml.bind.DatatypeConverter;
import java.io.BufferedWriter;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

/**
 * Created by Sudhir_Kumar on 5/9/2017.
 */
public class DataToHashList {
    public static final int bufferSize = 16;

    public ArrayList<byte []>   data;
    public ArrayList<String>    hashList;

    private byte[] currentBuffer;
    private int pos;

    public DataToHashList() {
        data = new ArrayList<byte[]>();
        hashList = new ArrayList<String>();
        currentBuffer = new byte[bufferSize];
        pos = 0;
        data.add(currentBuffer);
    }

    public void insertBuffer(byte[] newBuffer, int buflen) {
        int     i,j;

        if ( (pos + buflen) <= bufferSize){
            for (i=0; i<buflen; i++){
                currentBuffer[pos + i] = newBuffer[i];
            }
            if ((pos + buflen) == bufferSize) {
                currentBuffer = new byte[bufferSize];
                data.add(currentBuffer);
                pos = 0;
            } else {
                pos = pos + buflen;
            }
        } else {
            for (i=0; i < (bufferSize-pos); i++) {
                currentBuffer[pos + i] = newBuffer[i];
            }
            currentBuffer = new byte[bufferSize];
            data.add(currentBuffer);
            for (i=bufferSize-pos, j=0; i<buflen; i++, j++) {
                currentBuffer[j] = newBuffer[i];
            }
            pos = j;
        }
        System.out.println("data.size():" + data.size());
    }

    public void computeHashlist() throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");

        for (byte[] block : data) {
            md.update(block, 0, block.length);
            byte[] digest = md.digest();
            String myhash = DatatypeConverter.printHexBinary(digest).toUpperCase();
            hashList.add(myhash);
        }
    }

    public void show(BufferedWriter outf) {
        for (String md5hash : hashList) {
            try {
                outf.write(md5hash + "\n");
            } catch (IOException e) {
                e.printStackTrace();
            }
            System.out.println(md5hash);
        }
    }
}
