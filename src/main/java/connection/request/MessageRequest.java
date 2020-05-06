package connection.request;

import connection.Message;
import connection.MessageReceiver;
import security.AESManager;
import security.CipherManager;
import security.MACManager;
import security.SecurityParameters;
import connection.MessageSender;
import util.AppParameters;
import util.AppMenu;
import util.PeerModel;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Base64;

public class MessageRequest implements Runnable, Message {

    private Socket clientSocket = null;
    private PeerModel peer;

    private BufferedReader in;
    private PrintWriter out;

    public MessageRequest(PeerModel peer) {
        this.peer = peer;
    }

    @Override
    public void run() {

        try {
            // open socket
            clientSocket = new Socket(peer.getIp(), peer.getPort());
            in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            out  = new PrintWriter(clientSocket.getOutputStream(), true);
            System.out.println("[INFO] Connection established with: " + peer.getUserName());
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println("[ERROR] Connection refused: " + peer.getUserName());
            endCommunication("Could not connect to user");
            return;
        }
        AppParameters.inCommunication = true;

        // handshake operation
        String ownMasterSecret, peerMasterSecret;
        try {
            // handshake request
            HandshakeRequest handshake = new HandshakeRequest(in, out);
            int status = handshake.run();

            if (status == -1){
                // error
                closeConnection("Could not connect to user");
                return;
            } else if (status == -2){
                //user busy
                closeConnection("User is busy");
                return;
            }
            SecurityParameters.peerPublicKey = handshake.getPeerPublicKey();
            ownMasterSecret = handshake.getOwnMasterSecret();
            peerMasterSecret = handshake.getPeerMasterSecret();
        } catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException | IllegalBlockSizeException | BadPaddingException | NoSuchPaddingException | IOException | CertificateException | SignatureException e) {
            e.printStackTrace();
            closeConnection(null);
            return;
        }

        try {
            // parse aes keys
            String[] keysB64 = ownMasterSecret.split(":");
            SecurityParameters.ownIvKey = new IvParameterSpec(Base64.getDecoder().decode(keysB64[0]));
            SecurityParameters.ownMacKey = new SecretKeySpec(Base64.getDecoder().decode(keysB64[1]), SecurityParameters.macEncryptionMethod);
            SecurityParameters.ownAesKey = new SecretKeySpec(Base64.getDecoder().decode(keysB64[2]), SecurityParameters.aesKeyMethod);

            String[] peerKeysB64 = peerMasterSecret.split(":");
            SecurityParameters.peerIvKey = new IvParameterSpec(Base64.getDecoder().decode(peerKeysB64[0]));
            SecurityParameters.peerMacKey = new SecretKeySpec(Base64.getDecoder().decode(peerKeysB64[1]), SecurityParameters.macEncryptionMethod);
            SecurityParameters.peerAesKey = new SecretKeySpec(Base64.getDecoder().decode(peerKeysB64[2]), SecurityParameters.aesKeyMethod);

            System.out.println("[INFO] AES keys parsed");

        } catch (Exception e) {
            e.printStackTrace();
            // close connections
            closeConnection(null);
            System.out.println("[ERROR] Connection closed -1");
        }

        MessageSender ms = new MessageSender(this, out, peer.getUserName());
        new Thread(ms).start();

        MessageReceiver mr = new MessageReceiver(this, in, peer.getUserName());
        new Thread(mr).start();

    }

    public void closeConnection(String message){
        // close connections
        try {
            in.close();
            out.close();
            clientSocket.close();
        } catch (IOException e) {
            e.printStackTrace();
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
