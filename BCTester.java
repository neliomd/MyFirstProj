
import ByteCache.DataToHashList;
import ByteCache.HashInfo;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;

/**
 * Created by Sudhir_Kumar on 5/10/2017.
 */
public class BCTester {
    public static void main(String[] args){
        DataToHashList  dthl = new DataToHashList();
        byte [] buf = new byte[18];
        for (int i=0; i<18; i++) {
            buf[i] = (byte) (i+30);
        }
        dthl.insertBuffer(buf, 18);

        for (int i=0; i<18; i++) {
            buf[i] = (byte) (i+50);
        }
        dthl.insertBuffer(buf, 18);
        try {
            dthl.computeHashlist();
        } catch (NoSuchAlgorithmException e){
            e.printStackTrace();
        }
        //E25885E9BA19A3AC262FD372CF89EA38

        BufferedWriter bw = null;
        FileWriter     fw = null;

        try {
            fw = new FileWriter("myout.txt");
            bw = new BufferedWriter(fw);
            bw.write("Beginning of file:\n");
            dthl.show(bw);

        } catch (IOException e) {
            e.printStackTrace();
        } finally {
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
}
