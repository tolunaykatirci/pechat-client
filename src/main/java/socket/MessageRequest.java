package socket;

import security.CipherHelper;
import security.SecurityHelper;
import socket.request.HandshakeRequest;
import util.AppConfig;
import util.CommunicationController;
import util.MenuThread;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Scanner;

public class MessageRequest implements Runnable, Message {

    private Socket clientSocket = null;
    private String ip;
    private int port;

    private BufferedReader in;
    private PrintWriter out;

    private String peerCertificateB64;
    private PublicKey peerPublicKey;
    private String masterSecret;

    private IvParameterSpec ivKey;
    private SecretKey macKey;
    private SecretKey aesKey;

    private Mac mac;

    public MessageRequest() {
        this.ip = AppConfig.appProperties.getPeerIp();
        this.port = AppConfig.appProperties.getPeerPort();
    }

    @Override
    public void run() {

        try {
            // open socket
            clientSocket = new Socket(ip,port);
            in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            out  = new PrintWriter(clientSocket.getOutputStream(), true);


            // handshake request
            HandshakeRequest handshake = new HandshakeRequest(in, out);
            handshake.run();
            peerCertificateB64 = handshake.getPeerCertificateB64();
            peerPublicKey = handshake.getPeerPublicKey();
            masterSecret = handshake.getMasterSecret();
            System.out.println("[INFO] Master Secret: " + masterSecret);

            // parse aes keys
            String[] keysB64 = masterSecret.split(":");
            ivKey = new IvParameterSpec(Base64.getDecoder().decode(keysB64[0]));
            macKey = new SecretKeySpec(Base64.getDecoder().decode(keysB64[1]), "AES");
            aesKey = new SecretKeySpec(Base64.getDecoder().decode(keysB64[2]), "AES");
            System.out.println("[INFO] AES keys parsed");


            // generate mac
            mac = Mac.getInstance(CipherHelper.macEncryptionMethod);
            mac.init(macKey);
            System.out.println("[INFO] MAC generated");

            MessageSenderThread mst = new MessageSenderThread(this, out);
            new Thread(mst).start();

            String line;
            while ((line = in.readLine())!= null){
                if (line.equals("!exit")){
                    closeConnection();
                    System.out.println("[INFO] connection closed by Bob");
                    break;
                } else {
                    System.out.println("[Bob]: " + line);
                }
            }

//            closeConnection();
//            System.out.println("[INFO] Connection closed 0");


        } catch (IOException | CertificateException | NoSuchAlgorithmException | InvalidKeyException | SignatureException | NoSuchProviderException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
            // close connections
            closeConnection();
            System.out.println("[INFO] Connection closed -1");
        }

    }

    public void closeConnection(){
        // close connections
        try {
            in.close();
            out.close();
            clientSocket.close();

            CommunicationController.inCommunication = false;
            MenuThread menu = new MenuThread();
            new Thread(menu).start();

        } catch (IOException e) {
            e.printStackTrace();
        }

    }

}
