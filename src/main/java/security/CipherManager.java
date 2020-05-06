package security;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.util.Base64;

import static security.SecurityParameters.keyEncryptionMethod;

public class CipherManager {


    public static String encrypt(PublicKey publicKey, String message) {
        try {
            Cipher encrypt = Cipher.getInstance(keyEncryptionMethod);
            encrypt.init(Cipher.ENCRYPT_MODE, publicKey);

            byte[] encryptedMessage = encrypt.doFinal(message.getBytes());
            String encryptedMessageB64 = Base64.getEncoder().encodeToString(encryptedMessage);
            System.out.println("[INFO] Message Key encrypted: " + encryptedMessageB64);

            return encryptedMessageB64;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException | InvalidKeyException e) {
            e.printStackTrace();
            System.out.println("[ERROR] Error on Key encryption");
        }
        return null;
    }

    public static String decrypt(PrivateKey privateKey, String encryptedMessageB64) {
        try {
            Cipher decrypt = Cipher.getInstance(keyEncryptionMethod);
            decrypt.init(Cipher.DECRYPT_MODE, privateKey);

            byte[] encryptedMessage = Base64.getDecoder().decode(encryptedMessageB64);
            String decryptedMessage = new String(decrypt.doFinal(encryptedMessage));
            System.out.println("[INFO] Message Key decrypted: " + decryptedMessage);

            return decryptedMessage;
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
            System.out.println("[ERROR] Error on Key decryption");
        }
        return null;
    }

    public static String sign(PrivateKey privateKey, String data){
        try {
            Signature sign = Signature.getInstance(SecurityParameters.keySignMethod);
            sign.initSign(privateKey);
            //Adding data to the signature
            sign.update(data.getBytes());
            byte[] signedMessage = sign.sign();

            String signedMessageB64 = Base64.getEncoder().encodeToString(signedMessage);
            System.out.println("[INFO] Message signed: " + signedMessageB64);

            return signedMessageB64;

        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
            System.out.println("[ERROR] Error on message sign");
        }

        return null;
    }

    public static boolean verify(PublicKey publicKey, byte[] originalData, byte[] signedData) {

        try {
            // compute SHA256withRSA as a single step
            Signature sign = Signature.getInstance(SecurityParameters.keySignMethod);
            sign.initVerify(publicKey);
            sign.update(originalData);
            //Verifying the signature

            boolean res = sign.verify(signedData);
            if (res)
                System.out.println("[INFO] Message verified");
            else
                System.out.println("[ERROR] Error on message verify");

            return res;

        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
            System.out.println("[ERROR] Error on message verify");
        }

        return false;
    }

    public static byte[] generateRandomBytes(int size) {
        byte[] bytes = new byte[size];
        SecureRandom random = new SecureRandom();
        random.nextBytes(bytes);
        return bytes;
    }
}
