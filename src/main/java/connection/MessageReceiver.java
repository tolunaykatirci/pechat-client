package connection;

import security.AESManager;
import security.CipherManager;
import security.MACManager;
import security.SecurityParameters;
import util.AppConfig;
import util.AppParameters;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Date;
import java.util.logging.Logger;

public class MessageReceiver implements Runnable {

    private static Logger log = AppConfig.getLogger(MessageReceiver.class.getName());

    private BufferedReader in;
    private Message m;
    private String peerUserName;
    private int sequence;

    public MessageReceiver(Message m, BufferedReader in, String peerUserName) {
        this.in = in;
        this.m = m;
        this.peerUserName = peerUserName;
        this.sequence = 0;
    }

    @Override
    public void run() {

        try {
            String line;
            while ((line = in.readLine())!= null){

                log.info("[RECEIVED] " + line);

                // Step 1. Decrypt message with AES key
                String aesDecryptedMessage = AESManager.decrypt(line);
                if (aesDecryptedMessage == null)
                    continue;

                String [] splitted = aesDecryptedMessage.split(":");
                if(splitted.length != 4){
                    log.warning("[ERROR] Message could not split");
                    continue;
                }

                // Step 2. Get HMAC, message, sequence and message time
                String message = splitted[0];
                int messageSequence = Integer.parseInt(splitted[1]);
                long messageTime = Long.parseLong(splitted[2]);
                String messageHMAC = splitted[3];

                // Step 3. Check is message time expired
                long currentTime = System.currentTimeMillis();
                if (currentTime-messageTime > 60 * 1000) {
                    // message expired
                    log.warning("Message expired!");
                    continue;
                }

                // Step 4. Check is message's sequence correct
                if (sequence != messageSequence){
                    // message sequence is wrong
                    log.warning("Message sequence is wrong!");
                    continue;
                }
                sequence++;

                // Step 5. Check HMAC equality for integrity check
                String messageConcat = splitted[0]+":"+splitted[1]+":"+splitted[2];
                String messageHMAC2 = MACManager.calculateHMAC(messageConcat, SecurityParameters.peerMacKey);
                if (messageHMAC2 == null)
                    continue;

                if (!messageHMAC2.equals(messageHMAC)){
                    log.warning("[ERROR] Message authentication error");
                    continue;
                }



                if (message.equals("!exit")){
                    m.closeConnection("Connection closed by " + peerUserName);
                    log.info("connection closed by " + peerUserName);
                    break;
                } else {
                    System.out.println("["+peerUserName+"]: " + message);
                }
            }
        } catch (IOException e) {
            log.warning(e.getMessage());
            log.warning("[ERROR] Input error");
        }

    }
}
