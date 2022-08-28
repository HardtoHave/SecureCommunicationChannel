package Bob;

import Alice.RSA;
import Alice.testRC4;
import Gen.Prefab;

import java.io.IOException;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.PublicKey;
import java.util.Random;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class readFile2 {

    public boolean sha1Message(InetAddress IP, DatagramSocket clientSocket, String sessionKey, testRC4 rc) {
        int portno = 9876;
        Scanner sc = new Scanner(System.in);
        int inside = 0;
        System.out.println("Enter: quit to exit the program");
        Prefab prefab=new Prefab();
        while (true) {
            if (inside == 1) {
                try {
                    //receive from server
                    byte[] receivebuffer = new byte[1024];
                    DatagramPacket receivePacket = new DatagramPacket(receivebuffer, receivebuffer.length);
                    clientSocket.receive(receivePacket);

                    byte[] storing = new byte[receivePacket.getLength()];
                    System.arraycopy(receivebuffer, 0, storing, 0, receivePacket.getLength());
                    System.out.print("Server: ");
                    String printing = prefab.decryptMessage(storing, rc,sessionKey);
                    System.out.println(printing);
                }catch (Exception e){
                    System.out.println("Decryption Error”");
                }
            }

            System.out.print("Client: ");
            String sendMsg = sc.nextLine();

            byte[] sendbuffer;
            try {
                if (sendMsg.equals("exit")) {
                    System.out.println("Client shutting down");
                    sendbuffer = prefab.encryptMessage(sendMsg, rc,sessionKey);
                    DatagramPacket sendPacket = new DatagramPacket(sendbuffer, sendbuffer.length, IP, portno);
                    clientSocket.send(sendPacket);
                    break;
                }

                sendbuffer = prefab.encryptMessage(sendMsg, rc, sessionKey);
                DatagramPacket sendPacket = new DatagramPacket(sendbuffer, sendbuffer.length, IP, portno);
                clientSocket.send(sendPacket);
                inside = 1;
            }catch (Exception e){
                System.out.println("Decryption Error”");
            }
        }
        return true;
    }


    public boolean checkPW(boolean shutDownSystem, byte[] receivebuffer, InetAddress IP, DatagramSocket clientSocket, testRC4 rc, int portno, PublicKey publicKey) throws IOException {
        boolean ok = true;
        String pw;
        Scanner s = new Scanner(System.in);
        while (ok) {
            System.out.println("To quit please enter: exit");
            System.out.print("Please enter the password: ");
            pw = s.next();
            //check password with server
            String encrypted = "";
            byte[] enText = encrypted.getBytes();


            try {
                enText= RSA.encrypt(pw,publicKey).getBytes();
            } catch (Exception e) {
                e.printStackTrace();
            }

            //check if user typed exit
            byte[] sendbuffer;
            if (pw.equals("exit")) {
                System.out.println("Good bye, client shutting down");
                shutDownSystem = true;
                sendbuffer = enText;
                DatagramPacket sendPacket = new DatagramPacket(sendbuffer, sendbuffer.length, IP, portno);
                clientSocket.send(sendPacket);
                break;
            }

            sendbuffer = enText;
            DatagramPacket sendPacket = new DatagramPacket(sendbuffer, sendbuffer.length, IP, portno);
            clientSocket.send(sendPacket);

            //receive from server
            DatagramPacket receivePacket = new DatagramPacket(receivebuffer, receivebuffer.length);
            clientSocket.receive(receivePacket);
            byte[] data = receivePacket.getData();

            byte[] deText = rc.decrypt(data);

            String con = new String(deText);
            String trueOrFalse = con.substring(0, 4);

            if (trueOrFalse.equals("true")) {
                System.out.println("Connection Okay");
                ok = false;
            } else {
                System.out.println("Connection Failed");
                System.out.println("Incorrect password, please try again");
            }
        }
        return shutDownSystem;
    }

    public String generateSessionKey(String p, String g, byte[] receivebuffer, InetAddress IP, DatagramSocket clientSocket, testRC4 rc, int portno) throws IOException {
        BigInteger bigG;
        BigInteger bigP;
        BigInteger sessionKey;
        BigInteger NB;
        BigInteger NA;
        BigInteger XB;
        String s;
        int pp = Integer.parseInt(p);
        int gg = Integer.parseInt(g);

        bigG = BigInteger.valueOf(gg);
        bigP = BigInteger.valueOf(pp);


        String encrypted;
        byte[] enText;


        Random rand = new Random();
        int xb = rand.nextInt(pp - 2) + 1;
        //generate YB
        XB = BigInteger.valueOf(xb);
        NB = bigG.modPow(XB, bigP);

        String NBB = String.valueOf(NB);

        encrypted = "";
        enText = encrypted.getBytes();
        //encrypt YBB
        try {
            enText = rc.encrypt(NBB.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }

        System.out.println("Generating NB and communicating with server...");
        System.out.println("Sending NB to server...");
        byte[] sendbuffer = enText;

        DatagramPacket sendPacket = new DatagramPacket(sendbuffer, sendbuffer.length, IP, portno);
        clientSocket.send(sendPacket);

        //receive from server
        DatagramPacket receivePacket = new DatagramPacket(receivebuffer, receivebuffer.length);
        clientSocket.receive(receivePacket);
        byte[] data = receivePacket.getData();
        byte[] deText = rc.decrypt(data);

        String con = new String(deText);

        Pattern ppp = Pattern.compile("\\d+");
        Matcher m = ppp.matcher(con);
        int na = 0;
        if (m.find()) {
            na = Integer.parseInt(m.group(0));
        }

        NA = BigInteger.valueOf(na);
        sessionKey = NA.modPow(XB, bigP);
        s = sessionKey.toString();

        return s;
    }

}
