package security;

import util.AppConfig;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.logging.Logger;

public class MACManager {

    private static Logger log = AppConfig.getLogger(MACManager.class.getName());

    public static String calculateHMAC(String message, SecretKey macKey) {
        try {
            Mac mac = Mac.getInstance(SecurityParameters.macEncryptionMethod);
            mac.init(macKey);

            String calculatedHMAC = Base64.getEncoder().encodeToString(mac.doFinal(message.getBytes()));
            log.info("HMAC Calculated: " + calculatedHMAC);

            return calculatedHMAC;
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            log.warning(e.getMessage());
            log.warning("[ERROR] Error on HMAC");
        }
        return null;
    }
}
