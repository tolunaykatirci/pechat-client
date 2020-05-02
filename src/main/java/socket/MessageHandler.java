package socket;

import socket.handler.HandshakeHandler;
import util.CommunicationController;
import util.MenuThread;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Base64;

public class MessageHandler implements Runnable, Message {

    private Socket clientSocket;
    private BufferedReader in;
    private PrintWriter out;

    private String peerCertB64;
    private PublicKey peerPublicKey;
    private String masterSecret;

    private IvParameterSpec ivKey;
    private SecretKey macKey;
    private SecretKey aesKey;


    public MessageHandler(Socket clientSocket, BufferedReader in, PrintWriter out, String peerCertB64){
        this.clientSocket = clientSocket;
        this.in = in;
        this.out = out;
        this.peerCertB64 = peerCertB64;
    }

    @Override
    public void run() {

        try {
            CommunicationController.inCommunication = true;

            HandshakeHandler handshakeHandler = new HandshakeHandler(in, out, peerCertB64);
            handshakeHandler.run();
            peerPublicKey = handshakeHandler.getPeerPublicKey();
            masterSecret = handshakeHandler.getMasterSecret();

            String[] keysB64 = masterSecret.split(":");
            ivKey = new IvParameterSpec(Base64.getDecoder().decode(keysB64[0]));
            macKey = new SecretKeySpec(Base64.getDecoder().decode(keysB64[1]), "AES");
            aesKey = new SecretKeySpec(Base64.getDecoder().decode(keysB64[2]), "AES");
            System.out.println("[INFO] AES keys parsed");


//            String line;
//            while ((line = in.readLine())!= null){
//                System.out.println("[Alice]: " + line);
//            }


            MessageSenderThread mst = new MessageSenderThread(this, out);
            new Thread(mst).start();

            String line;
            while ((line = in.readLine())!= null){
                if (line.equals("!exit")){
                    closeConnection();
                    System.out.println("[INFO] connection closed by Alice");
                    break;
                } else {
                    System.out.println("[Alice]: " + line);
                }
            }

//            closeConnection();
//            System.out.println("[INFO] connection closed 0");

        } catch (IOException | CertificateException | NoSuchAlgorithmException | InvalidKeyException | SignatureException | NoSuchProviderException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
            closeConnection();
            System.out.println("[INFO] connection closed -1");
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
