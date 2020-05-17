package connection;

import lombok.Getter;
import security.AESManager;
import security.CipherManager;
import security.MACManager;
import security.SecurityParameters;
import util.AppConfig;
import util.AppParameters;

import java.io.PrintWriter;
import java.util.logging.Logger;

@Getter
public class MessageSender implements Runnable {

    private static Logger log = AppConfig.getLogger(MessageSender.class.getName());

    private PrintWriter out;
    private Message m;
    private String peerUserName;
    private int sequence;

    public MessageSender(Message m, PrintWriter out, String peerUserName) {
        this.out = out;
        this.m = m;
        this.peerUserName = peerUserName;
        this.sequence = 0;
    }

    @Override
    public void run() {

        while (AppParameters.inCommunication){
            if(AppParameters.reader.isReady()){
                String message = AppParameters.reader.readLine();
                log.info("Typed: " + message);


                // Step 1. Get current time to prevent replay attack
                long currentTime = System.currentTimeMillis();

                // Step 2. Concatenate message sequence and current time to prevent replay attack
                String messageConcat = message + ":" + (sequence++) + ":" + currentTime;

                // Step 3. Generate HMAC of message for message integrity
                String messageHMAC = MACManager.calculateHMAC(messageConcat, SecurityParameters.ownMacKey);
                if (messageHMAC == null)
                    continue;

                // Step 4. Concatenate HMAC and message
                String messageHMACConcat = messageConcat + ":" + messageHMAC;

                // Step 5. Encrypt message with AES
                String aesEncryptedMessage = AESManager.encrypt(messageHMACConcat);
                if (aesEncryptedMessage == null)
                    continue;


                out.println(aesEncryptedMessage);
                out.flush();
                log.info("[SENT] " + aesEncryptedMessage);

                if (message.equals("!exit")){
                    m.closeConnection("Connection closed");
                    break;
                }
            }
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                log.warning(e.getMessage());
            }

        }
    }
}
