package security;

import socket.ServerManager;
import util.AppConfig;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.logging.Logger;

public class KeyManager {

    private static Logger log = AppConfig.getLogger(KeyManager.class.getName());

    public static boolean initialKeyPairCheck(){
        File pubKey = new File(AppConfig.appProperties.getPublicKeyPath());
        File pvtKey = new File(AppConfig.appProperties.getPrivateKeyPath());

        if (pubKey.exists() && pvtKey.exists()) {
            SecurityParameters.ownPublicKey = loadPublicKey(AppConfig.appProperties.getPublicKeyPath());
            SecurityParameters.ownPrivateKey = loadPrivateKey(AppConfig.appProperties.getPrivateKeyPath());
            log.info("Public/Private keys loaded from file");

        } else {
            KeyPair kp = generateKeyPair();
            if(kp != null) {
                SecurityParameters.ownPublicKey = kp.getPublic();
                SecurityParameters.ownPrivateKey = kp.getPrivate();
                log.info("Public/Private keys generated for the first time");

            } else {
                log.warning("Could not create Key Pair!");
                return false;
            }
        }

        String serverPubB64 = ServerManager.getServerPublicKey();
        if (serverPubB64 != null){
            byte[] serverPub = Base64.getDecoder().decode(serverPubB64);
            SecurityParameters.serverPublicKey = convertToPublicKey(serverPub);
            log.info("Server Public Key loaded");
        } else {
            log.warning("Server Public Key could not load");
            return false;
        }
        return true;
    }

    public static KeyPair generateKeyPair() {
        KeyPair kp = null;
        try {
            KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
            keygen.initialize(2048);

            kp = keygen.generateKeyPair();

            PublicKey pub = kp.getPublic();
            PrivateKey pvt = kp.getPrivate();

            saveKey(pub.getEncoded(), AppConfig.appProperties.getPublicKeyPath());
            saveKey(pvt.getEncoded(), AppConfig.appProperties.getPrivateKeyPath());

        } catch (NoSuchAlgorithmException e) {
            log.warning(e.getMessage());
        }
        return kp;
    }

    public static PublicKey convertToPublicKey(byte[] bytes) {
        PublicKey pub = null;
        try {
            X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            pub = kf.generatePublic(ks);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            log.warning(e.getMessage());
        }
        return pub;
    }


    public static void saveKey(byte [] key, String fileName) {
        try {
            FileOutputStream out = new FileOutputStream(fileName);
            out.write(key);
            out.close();
            log.info("Key saved to: " + fileName);
        } catch (IOException e) {
            log.warning(e.getMessage());
        }
    }

    public static PublicKey loadPublicKey(String filePath) {
        PublicKey pub = null;
        try {
            Path path = Paths.get(filePath);
            byte[] bytes = Files.readAllBytes(path);
            X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            pub = kf.generatePublic(ks);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            log.warning(e.getMessage());
        }
        return pub;
    }

    public static PrivateKey loadPrivateKey(String filePath) {
        PrivateKey pvt = null;
        try {
            Path path = Paths.get(filePath);
            byte[] bytes = Files.readAllBytes(path);

            PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(bytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            pvt = kf.generatePrivate(ks);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            log.warning(e.getMessage());
        }
        return pvt;
    }

    public static String generateMasterSecret() {
        byte[] iv = CipherManager.generateRandomBytes(16);
        byte[] macSecret = CipherManager.generateRandomBytes(32);
        byte[] aesSecret = CipherManager.generateRandomBytes(32); // 256 bits

        return Base64.getEncoder().encodeToString(iv)
                + ":" + Base64.getEncoder().encodeToString(macSecret)
                + ":" + Base64.getEncoder().encodeToString(aesSecret);
    }
}
