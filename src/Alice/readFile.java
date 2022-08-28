package Alice;

import Gen.Prefab;

import java.io.IOException;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.PrivateKey;
import java.util.Random;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class readFile {
    private static int portno = 9876;
    private static
    InetAddress IP = null;
    public boolean sha1Message(String sessionKey, DatagramSocket serverSocket, testRC4 rc) {
        byte[] receivebuffer;
        byte[] sendbuffer;
        boolean ok = true;
        System.out.println("Server waiting message...");
        Scanner sc = new Scanner(System.in);
        int inside = 1;
        String serverMsg;
        String printing;
        Prefab prefab=new Prefab();
        while (ok) {
            if (inside == 1) {
                try {
                    receivebuffer = new byte[1024];
                    DatagramPacket receivePacket = new DatagramPacket(receivebuffer, receivebuffer.length);
                    serverSocket.receive(receivePacket);

                    byte[] storing = new byte[receivePacket.getLength()];
                    System.arraycopy(receivebuffer, 0, storing, 0, receivePacket.getLength());
                    printing = prefab.decryptMessage(storing, rc,sessionKey);

                    if (printing.equalsIgnoreCase("exit")) {
                        ok = false;
                        System.out.println("Client exited the program, server shutting down");
                        break;
                    }
                    System.out.println("Client: " + printing);
                    inside = 0;
                } catch (Exception e) {
                   e.printStackTrace();
                }
            }

            if (inside == 0) {
                try {
                    System.out.print("Server: ");
                    serverMsg = sc.nextLine();

                    sendbuffer = prefab.encryptMessage(serverMsg, rc,sessionKey);
                    DatagramPacket sendPacket = new DatagramPacket(sendbuffer, sendbuffer.length, IP, portno);
                    serverSocket.send(sendPacket);
                    inside = 1;

                } catch (Exception e) {
                    System.out.println("Decryption Error”");
                }
            }
        }

        return true;
    }
    public boolean checkPW(boolean shutDownSystem, String password, testRC4 rc, DatagramSocket serverSocket, PrivateKey privateKey) throws Exception {

        byte[] receivebuffer = new byte[1024];
        byte[] sendbuffer;

        boolean ok = true;

        System.out.println("Awaiting client to key in password...");
        while (ok) {
            DatagramPacket receivePacket = new DatagramPacket(receivebuffer, receivebuffer.length);
            serverSocket.receive(receivePacket);
            IP = receivePacket.getAddress();
            portno = receivePacket.getPort();

            byte[] storing = new byte[receivePacket.getLength()];
            System.arraycopy(receivebuffer, 0, storing, 0, receivePacket.getLength());
            storing= RSA.decrypt(new String(storing),privateKey).getBytes();
            String con = new String(storing);

            if (con.equalsIgnoreCase("exit")) {
                System.out.println("Client had exited the program, server shutting down");
                shutDownSystem = true;
                break;
            }

            if (con.equals(password)) {
                System.out.println("Password correct");
                System.out.println("Connection Okay");
                ok = false;

                String encrypted = "";
                byte[] enText = encrypted.getBytes();
                String plainText = "true";
                try {
                    enText = rc.encrypt(plainText.getBytes());
                } catch (Exception e) {
                    e.printStackTrace();
                }
                sendbuffer = enText;
                DatagramPacket sendPacket = new DatagramPacket(sendbuffer, sendbuffer.length, IP, portno);
                serverSocket.send(sendPacket);
            } else {
                System.out.println("Incorrect password");
                String plainText = "false";
                byte[] enText = "".getBytes();
                try {
                    enText = rc.encrypt(plainText.getBytes());
                } catch (Exception e) {
                    e.printStackTrace();
                }

                sendbuffer = enText;
                DatagramPacket sendPacket = new DatagramPacket(sendbuffer, sendbuffer.length, IP, portno);
                serverSocket.send(sendPacket);
            }
        }

        return shutDownSystem;
    }

    public String generateSessionKey(BigInteger p, BigInteger g, testRC4 rc, DatagramSocket serverSocket, Random rand) throws IOException {

        BigInteger sessionKey;
        BigInteger NB;
        BigInteger NA;
        BigInteger XA;
        String s;
        byte[] receivebuffer = new byte[1024];
        byte[] sendbuffer;
        DatagramPacket receivePacket = new DatagramPacket(receivebuffer, receivebuffer.length);
        serverSocket.receive(receivePacket);
        byte[] clientData = receivePacket.getData();

        byte[] deText = rc.decrypt(clientData);

        String con = new String(deText);

        Pattern pp = Pattern.compile("\\d+");
        Matcher m = pp.matcher(con);
        int yb = 0;
        if (m.find()) {
            yb = (int) Long.parseLong(m.group(0));
        }

        int smallP = p.intValue();
        int xa = rand.nextInt(smallP - 2) + 1;

        //getting session key
        NB = BigInteger.valueOf(yb);
        XA = BigInteger.valueOf(xa);
        sessionKey = NB.modPow(XA, p);

        //send NA
        System.out.println("Generating NA and sending to client...");
        NA = g.modPow(XA, p);
        String NAA = String.valueOf(NA);

        String encrypted = "";
        byte[] enText = encrypted.getBytes();
        //encrypt YA
        try {
            enText = rc.encrypt(NAA.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
        sendbuffer = enText;
        System.out.println("NA sent to client and awaiting message from client...");

        DatagramPacket sendPacket = new DatagramPacket(sendbuffer, sendbuffer.length, IP, portno);
        serverSocket.send(sendPacket);

        s = sessionKey.toString();
        return s;
    }

}
