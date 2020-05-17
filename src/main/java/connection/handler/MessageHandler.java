package connection.handler;

import connection.Message;
import connection.MessageReceiver;
import security.AESManager;
import security.CipherManager;
import security.MACManager;
import security.SecurityParameters;
import connection.MessageSender;
import util.AppConfig;
import util.AppParameters;
import util.AppMenu;

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
import java.util.logging.Logger;

public class MessageHandler implements Runnable, Message {

    private static Logger log = AppConfig.getLogger(MessageHandler.class.getName());

    private Socket clientSocket;
    private BufferedReader in;
    private PrintWriter out;

    private String peerCertB64;
    private String peerUserName;


    public MessageHandler(Socket clientSocket, BufferedReader in, PrintWriter out, String peerUserName, String peerCertB64){
        this.clientSocket = clientSocket;
        this.in = in;
        this.out = out;
        this.peerUserName = peerUserName;
        this.peerCertB64 = peerCertB64;
    }

    @Override
    public void run() {
        String ownMasterSecret, peerMasterSecret;
        // handshake operation
        try {
            AppParameters.inCommunication = true;

            HandshakeHandler handshakeHandler = new HandshakeHandler(in, out, peerCertB64);
            handshakeHandler.run();
            SecurityParameters.peerPublicKey = handshakeHandler.getPeerPublicKey();
            ownMasterSecret = handshakeHandler.getOwnMasterSecret();
            peerMasterSecret = handshakeHandler.getPeerMasterSecret();

        } catch (IOException | CertificateException | NoSuchAlgorithmException | InvalidKeyException | SignatureException | NoSuchProviderException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException e) {
            log.warning(e.getMessage());
            closeConnection(null);
            log.info("connection closed -1");
            return;
        }

        try {
            String[] keysB64 = ownMasterSecret.split(":");
            SecurityParameters.ownIvKey = new IvParameterSpec(Base64.getDecoder().decode(keysB64[0]));
            SecurityParameters.ownMacKey = new SecretKeySpec(Base64.getDecoder().decode(keysB64[1]), SecurityParameters.macEncryptionMethod);
            SecurityParameters.ownAesKey = new SecretKeySpec(Base64.getDecoder().decode(keysB64[2]), SecurityParameters.aesKeyMethod);

            String[] peerKeysB64 = peerMasterSecret.split(":");
            SecurityParameters.peerIvKey = new IvParameterSpec(Base64.getDecoder().decode(peerKeysB64[0]));
            SecurityParameters.peerMacKey = new SecretKeySpec(Base64.getDecoder().decode(peerKeysB64[1]), SecurityParameters.macEncryptionMethod);
            SecurityParameters.peerAesKey = new SecretKeySpec(Base64.getDecoder().decode(peerKeysB64[2]), SecurityParameters.aesKeyMethod);

            log.info("AES keys parsed");
        }  catch (Exception e) {
            log.warning(e.getMessage());
            closeConnection(null);
            log.warning("Connection closed -1");
            return;
        }

        log.info("Connection established with: " + peerUserName);
        System.out.println("Connection established with: " + peerUserName);
        System.out.println("Please type !exit to end connection");

        MessageSender ms = new MessageSender(this, out, peerUserName);
        new Thread(ms).start();

        MessageReceiver mr = new MessageReceiver(this, in, peerUserName);
        new Thread(mr).start();

    }

    public void closeConnection(String message){
        // close connections
        try {
            in.close();
            out.close();
            clientSocket.close();
        } catch (IOException e) {
            log.warning(e.getMessage());
        }
        if (message == null)
            endCommunication("Connection closed");
        else
            endCommunication(message);
    }

    public void endCommunication(String message) {
        AppParameters.inCommunication = false;
        AppMenu menu = new AppMenu(message);
        new Thread(menu).start();
    }
}
