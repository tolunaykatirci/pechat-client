package connection;

import lombok.Getter;
import security.AESManager;
import security.CipherManager;
import security.MACManager;
import security.SecurityParameters;
import util.AppParameters;

import java.io.PrintWriter;

@Getter
public class MessageSender implements Runnable {

    private PrintWriter out;
    private Message m;
    private String peerUserName;

    public MessageSender(Message m, PrintWriter out, String peerUserName) {
        this.out = out;
        this.m = m;
        this.peerUserName = peerUserName;
    }

    @Override
    public void run() {

        while (AppParameters.inCommunication){
            if(AppParameters.reader.isReady()){
                String message = AppParameters.reader.readLine();

                // Step 1. Encrypt message with AES
                String aesEncryptedMessage = AESManager.encrypt(message);
                if (aesEncryptedMessage == null)
                    continue;

                // Step 2. Calculate HMAC
                String messageHMAC = MACManager.calculateHMAC(aesEncryptedMessage, SecurityParameters.ownMacKey);
                if (messageHMAC == null)
                    continue;

                // Step 3. Get current time to prevent replay attack
                long currentTime = System.currentTimeMillis();

                // Step 4. Concatenate HMAC and AES encrypted message and current time
                String messageHMACConcat = messageHMAC + ":" + aesEncryptedMessage + ":" + currentTime;

                // Step 5. Encrypt message with peer Public Key
                String peerEncryptedMessageB64 = CipherManager.encrypt(SecurityParameters.peerPublicKey, messageHMACConcat);
                if (peerEncryptedMessageB64 == null)
                    continue;

                out.println(peerEncryptedMessageB64);
                out.flush();
                System.out.println("[SENT] " + peerEncryptedMessageB64);

                if (message.equals("!exit")){
                    m.closeConnection("Connection closed");
                    break;
                }
            }
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }

        }
    }
}
