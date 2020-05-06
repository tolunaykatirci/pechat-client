package security;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

public class SecurityParameters {
    public static PublicKey ownPublicKey;
    public static PrivateKey ownPrivateKey;
    public static X509Certificate ownCertificate;
    public static PublicKey serverPublicKey;

    public static PublicKey peerPublicKey;

    public static String keyEncryptionMethod = "RSA/ECB/PKCS1Padding";
    public static String keySignMethod = "SHA256withRSA";
    public static String aesEncryptionMethod = "AES/CBC/PKCS5Padding";
    public static String macEncryptionMethod = "HMACSHA256";
    public static String aesKeyMethod = "AES";

    public static IvParameterSpec ownIvKey;
    public static SecretKey ownMacKey;
    public static SecretKey ownAesKey;

    public static IvParameterSpec peerIvKey;
    public static SecretKey peerMacKey;
    public static SecretKey peerAesKey;

}
