package security;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class MACManager {

    public static String calculateHMAC(String message, SecretKey macKey) {
        try {
            Mac mac = Mac.getInstance(SecurityParameters.macEncryptionMethod);
            mac.init(macKey);

            String calculatedHMAC = Base64.getEncoder().encodeToString(mac.doFinal(message.getBytes()));
            System.out.println("[INFO] HMAC Calculated: " + calculatedHMAC);

            return calculatedHMAC;
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
            System.out.println("[ERROR] Error on HMAC");
        }
        return null;
    }
}
