package security;

import util.AppConfig;

import javax.crypto.Cipher;
import java.util.Base64;
import java.util.logging.Logger;

public class AESManager {

    private static Logger log = AppConfig.getLogger(AESManager.class.getName());

    public static String encrypt(String message) {
        try {
            Cipher cipher = Cipher.getInstance(SecurityParameters.aesEncryptionMethod);
            cipher.init(Cipher.ENCRYPT_MODE, SecurityParameters.ownAesKey, SecurityParameters.ownIvKey);

            String encryptedMessageB64 = Base64.getEncoder().encodeToString(cipher.doFinal(message.getBytes()));
            log.info("Message AES Encrypted: " + encryptedMessageB64);

            return encryptedMessageB64;
        }
        catch (Exception e) {
            log.warning(e.getMessage());
            log.warning("[ERROR] Error on AES encryption");
        }
        return null;
    }

    public static String decrypt(String encryptedMessageB64) {
        try {
            byte[] encryptedMessage = Base64.getDecoder().decode(encryptedMessageB64);
            Cipher cipher = Cipher.getInstance(SecurityParameters.aesEncryptionMethod);
            cipher.init(Cipher.DECRYPT_MODE, SecurityParameters.peerAesKey, SecurityParameters.peerIvKey);

            String decryptedMessage = new String(cipher.doFinal(encryptedMessage));
            log.info("Message AES Decrypted: " + decryptedMessage);

            return decryptedMessage;
        }
        catch (Exception e) {
            log.warning(e.getMessage());
            log.warning("[ERROR] Error on AES decryption");
        }
        return null;
    }
}
