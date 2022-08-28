package Gen;

import Alice.GFG;
import Alice.testRC4;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.security.SecureRandom;
import java.util.Arrays;

public class Prefab {
    public static void main(String[] args) {
        String range="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        Prefab prefab=new Prefab();
        String commonPassword=prefab.generateCommonPassword(range);
        try{
            FileUtils.writeStringToFile(new File("/Users/robert/Desktop/A1/src/Gen/commonPassword.cp"),commonPassword);
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println(commonPassword);
    }
    public String generateCommonPassword(String range){
        SecureRandom rnd=new SecureRandom();
        StringBuilder stringBuilder=new StringBuilder();
        for (int i = 0; i < 8; i++) {
            stringBuilder.append(range.charAt(rnd.nextInt(range.length())));
        }
        return stringBuilder.toString();
    }
    public String generate(){
        SecureRandom rnd=new SecureRandom();
        StringBuilder stringBuilder=new StringBuilder();
        String range="0123456789";
        for (int i = 0; i < 8; i++) {
            stringBuilder.append(range.charAt(rnd.nextInt(range.length())));
        }
        return stringBuilder.toString();
    }
//    public String generateNAorNB(){
//        byte[] byteRandom=new byte[16];
//        new SecureRandom().nextBytes(byteRandom);
//        StringBuilder stringBuilder=new StringBuilder();
//        for (byte temp:byteRandom){
//            stringBuilder.append(String.format("%02x",temp));
//        }
//        return stringBuilder.toString();
//    }
    public byte[] encryptMessage(String serverMsg, testRC4 rc, String sessionKey){
        byte[] cipherText;
        try{
            String H = serverMsg + "||" +  sessionKey;
            String hashing = GFG.encryptThisString(H);
            String conHash = serverMsg + "||" + hashing;
            cipherText = rc.encrypt(conHash.getBytes());
        }
        catch(Exception e){
            e.printStackTrace();
            cipherText = new byte[1];
        }
        return cipherText;
    }

    public synchronized String decryptMessage(byte[] encrypted, testRC4 rc, String sessionKey){
        String returnMsg;
        byte[] deText = rc.decrypt(encrypted);
        String[] splitText = new String(deText).split("\\|\\|");
        String hash = splitText[1];
        String msg = splitText[0];
        String hPrime = GFG.encryptThisString(msg + "||" + sessionKey);

        if(hPrime.equals(hash)){
            returnMsg = msg;
        }
        else{
            returnMsg = "Someone tried to send a fake message";
        }
        return returnMsg;
    }
}
