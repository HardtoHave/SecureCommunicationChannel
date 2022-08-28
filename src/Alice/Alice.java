package Alice;

import Gen.Prefab;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.math.BigInteger;
import java.net.DatagramSocket;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Random;

public class Alice {
    public static void main(String[] args) throws Exception {
        boolean shutDownSystem=false;
        readFile rf = new readFile();
        String password= FileUtils.readFileToString(new File("/Users/robert/Desktop/A1/src/Gen/commonPassword.cp"));
        byte[] key = password.getBytes();

        KeyPair keyPair=RSA.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        byte[] privateKeyEncoded = privateKey.getEncoded();
        byte[] publicKeyEncoded = publicKey.getEncoded();
        String privateEncodeString = Base64.getEncoder().encodeToString(privateKeyEncoded);
        String publicEncodeString = Base64.getEncoder().encodeToString(publicKeyEncoded);
        FileUtils.writeStringToFile(new File("/Users/robert/Desktop/A1/src/Alice/a.pub"), publicEncodeString, String.valueOf(StandardCharsets.UTF_8));
        FileUtils.writeStringToFile(new File("/Users/robert/Desktop/A1/src/Alice/a.pri"), privateEncodeString, String.valueOf(StandardCharsets.UTF_8));
        FileUtils.writeStringToFile(new File("/Users/robert/Desktop/A1/src/Bob/a.pub"), publicEncodeString, String.valueOf(StandardCharsets.UTF_8));

        Prefab prefab=new Prefab();
        BigInteger p = new BigInteger(prefab.generate());
        FileUtils.writeStringToFile(new File("/Users/robert/Desktop/A1/src/Gen/p.pub"), p.toString(), String.valueOf(StandardCharsets.UTF_8));
        BigInteger g = new BigInteger(prefab.generate());
        FileUtils.writeStringToFile(new File("/Users/robert/Desktop/A1/src/Gen/g.pub"), g.toString(), String.valueOf(StandardCharsets.UTF_8));
        Random rand = new Random();

        testRC4 rc = new testRC4(new String(key));

        DatagramSocket serverSocket = new DatagramSocket(9876);

        String sessionKey = "";
        while(!shutDownSystem){
            shutDownSystem = rf.checkPW(false, password, rc, serverSocket,privateKey);
            //exchanging key with rc4
            if(!shutDownSystem){
                sessionKey = rf.generateSessionKey( p, g, rc,serverSocket, rand);
            }
            if(!shutDownSystem){

                shutDownSystem = rf.sha1Message(sessionKey, serverSocket, rc);
            }
        }
        serverSocket.close();
    }
}
