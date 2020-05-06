package connection;

import security.AESManager;
import security.CipherManager;
import security.MACManager;
import security.SecurityParameters;
import util.AppParameters;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Date;

public class MessageReceiver implements Runnable {

    private BufferedReader in;
    private Message m;
    private String peerUserName;

    public MessageReceiver(Message m, BufferedReader in, String peerUserName) {
        this.in = in;
        this.m = m;
        this.peerUserName = peerUserName;
    }

    @Override
    public void run() {

        try {
            String line;
            while ((line = in.readLine())!= null){

                System.out.println("[RECEIVED] " + line);

                // Step 1. Decrypt message with own private key
                String decryptedMessage = CipherManager.decrypt(SecurityParameters.ownPrivateKey, line);
                if (decryptedMessage == null)
                    continue;

                String [] splitted = decryptedMessage.split(":");
                if(splitted.length != 3){
                    System.out.println("[ERROR] Message could not split");
                    continue;
                }

                // Step 2. Get HMAC and AES encrypted message
                String messageHMAC = splitted[0];
                String aesEncryptedMessage = splitted[1];
                long messageTime = Long.parseLong(splitted[2]);

                // Step 3. Check is message time expired
                long currentTime = System.currentTimeMillis();
                if (currentTime-messageTime > 60 * 1000) {
                    // message expired
                    continue;
                }

                // Step 3. Check HMAC equality for integrity check
                String messageHMAC2 = MACManager.calculateHMAC(aesEncryptedMessage, SecurityParameters.peerMacKey);
                if (messageHMAC2 == null)
                    continue;

                if (!messageHMAC2.equals(messageHMAC)){
                    System.out.println("[ERROR] Message authentication error");
                    continue;
                }

                // Step 4. Decrypt AES encrypted message
                String aesDecryptedMessage = AESManager.decrypt(aesEncryptedMessage);
                if (aesDecryptedMessage == null)
                    continue;

                if (aesDecryptedMessage.equals("!exit")){
                    m.closeConnection("Connection closed by " + peerUserName);
                    System.out.println("[INFO] connection closed by " + peerUserName);
                    break;
                } else {
                    System.out.println("["+peerUserName+"]: " + aesDecryptedMessage);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println("[ERROR] Input error");
        }

    }
}
