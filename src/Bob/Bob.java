package Bob;

import Alice.testRC4;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Bob {
    public static void main(String[] args)throws Exception {
        readFile2 rf = new readFile2();


        String password = FileUtils.readFileToString(new File("/Users/robert/Desktop/A1/src/Gen/commonPassword.cp"));

        String p=FileUtils.readFileToString(new File("/Users/robert/Desktop/A1/src/Gen/p.pub"));
        String g =FileUtils.readFileToString(new File("/Users/robert/Desktop/A1/src/Gen/g.pub"));
        boolean shutDownSystem = false;
        String sessionKey = "";

        byte[] receivebuffer = new byte[1024];
        String readPK= Files.readString(Path.of("/Users/robert/Desktop/A1/src/Bob/a.pub"), Charset.defaultCharset());
        X509EncodedKeySpec spec=new X509EncodedKeySpec(Base64.getDecoder().decode(readPK));
        KeyFactory keyFactory=KeyFactory.getInstance("RSA");
        PublicKey publicKey=keyFactory.generatePublic(spec);
        //IP and socket
        InetAddress IP = InetAddress.getByName("127.0.0.1");
        DatagramSocket clientSocket = new DatagramSocket();
        byte[] key = password.getBytes();
        testRC4 rc = new testRC4(new String(key));
        int portno = 9876;

        while(!shutDownSystem){
            shutDownSystem = rf.checkPW(false, receivebuffer, IP, clientSocket, rc, portno,publicKey);
            if(!shutDownSystem){
                sessionKey = rf.generateSessionKey(p, g, receivebuffer, IP, clientSocket, rc, portno);
            }
            if(!shutDownSystem){
                shutDownSystem = rf.sha1Message(IP, clientSocket, sessionKey, rc);
            }
        }
        clientSocket.close();
    }
}
