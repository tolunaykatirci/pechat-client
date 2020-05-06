package security;

import javax.crypto.Cipher;
import java.util.Base64;

public class AESManager {

    public static String encrypt(String message) {
        try {
            Cipher cipher = Cipher.getInstance(SecurityParameters.aesEncryptionMethod);
            cipher.init(Cipher.ENCRYPT_MODE, SecurityParameters.ownAesKey, SecurityParameters.ownIvKey);

            String encryptedMessageB64 = Base64.getEncoder().encodeToString(cipher.doFinal(message.getBytes()));
            System.out.println("[INFO] Message AES Encrypted: " + encryptedMessageB64);

            return encryptedMessageB64;
        }
        catch (Exception e) {
            e.printStackTrace();
            System.out.println("[ERROR] Error on AES encryption");
        }
        return null;
    }

    public static String decrypt(String encryptedMessageB64) {
        try {
            byte[] encryptedMessage = Base64.getDecoder().decode(encryptedMessageB64);
            Cipher cipher = Cipher.getInstance(SecurityParameters.aesEncryptionMethod);
            cipher.init(Cipher.DECRYPT_MODE, SecurityParameters.peerAesKey, SecurityParameters.peerIvKey);

            String decryptedMessage = new String(cipher.doFinal(encryptedMessage));
            System.out.println("[INFO] Message AES Decrypted: " + decryptedMessage);

            return decryptedMessage;
        }
        catch (Exception e) {
            e.printStackTrace();
            System.out.println("[ERROR] Error on AES decryption");
        }
        return null;
    }
}
