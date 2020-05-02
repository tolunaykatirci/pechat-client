package security;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;

public class CipherHelper {

    public static String keyEncryptionMethod = "RSA/ECB/PKCS1Padding";
    public static String keySignMethod = "SHA256withRSA";
    public static String macEncryptionMethod = "HMACSHA256";
    public static String aesEncryptionMethod = "AES/CBC/PKCS5Padding";

    public static byte[] encrypt(PublicKey publicKey, String message) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher encrypt=Cipher.getInstance(keyEncryptionMethod);
        encrypt.init(Cipher.ENCRYPT_MODE, publicKey);
        return encrypt.doFinal(message.getBytes());
    }

    public static String decrypt(PrivateKey privateKey, byte[] message) throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
        Cipher decrypt=Cipher.getInstance(keyEncryptionMethod);
        decrypt.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(decrypt.doFinal(message), StandardCharsets.UTF_8);
    }

    public static byte[] sign(PrivateKey privateKey, String data) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
        Signature sign = Signature.getInstance(keySignMethod);
        sign.initSign(privateKey);
        //Adding data to the signature
        sign.update(data.getBytes());
        return sign.sign();
    }

    public static boolean verify(PublicKey publicKey, byte[] originalData, byte[] signedData) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        //compute SHA256withRSA as a single step
        Signature sign = Signature.getInstance(keySignMethod);
        sign.initVerify(publicKey);
        sign.update(originalData);
        //Verifying the signature
        return sign.verify(signedData);
    }

    public static SecretKeySpec getSecretKey(String masterSecret) {
        return new SecretKeySpec(masterSecret.getBytes(), macEncryptionMethod);
    }

    public static byte[] generateRandomBytes(int size) {
        byte[] bytes = new byte[size];
        SecureRandom random = new SecureRandom();
        random.nextBytes(bytes);
        return bytes;
    }
}
