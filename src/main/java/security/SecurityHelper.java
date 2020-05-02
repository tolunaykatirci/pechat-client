package security;

import socket.ServerRequest;
import util.AppConfig;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;

public class SecurityHelper {
    public static PublicKey clientPublicKey;
    public static PrivateKey clientPrivateKey;
    public static X509Certificate clientCertificate;
    public static PublicKey serverPublicKey;


    public static void initialKeyPairCheck(){
        File pubKey = new File(AppConfig.appProperties.getPublicKeyPath());
        File pvtKey = new File(AppConfig.appProperties.getPrivateKeyPath());

        if (pubKey.exists() && pvtKey.exists()) {
            clientPublicKey = loadPublicKey(AppConfig.appProperties.getPublicKeyPath());
            clientPrivateKey = loadPrivateKey(AppConfig.appProperties.getPrivateKeyPath());
            System.out.println("Public/Private keys loaded from file");
        } else {
            KeyPair kp = generateKeyPair();
            if(kp != null) {
                clientPublicKey = kp.getPublic();
                clientPrivateKey = kp.getPrivate();
                System.out.println("Public/Private keys generated for the first time");
            } else {
                System.out.println("Could not create Key Pair!");
            }
        }

        String serverPubB64 = new ServerRequest("serverPub").run();
        byte[] serverPub = Base64.getDecoder().decode(serverPubB64);
        serverPublicKey = loadPublicKey(serverPub);

        File certFile = new File(AppConfig.appProperties.getCertificatePath());
        if(certFile.exists()){
            // load certificate
            clientCertificate = loadCertificate(AppConfig.appProperties.getCertificatePath());
            System.out.println("Certificate loaded from file");
        } else {
            // get certificate from server
            String requestString = "register:" + AppConfig.appProperties.getUserName()
                    + ":" + AppConfig.appProperties.getPort()
                    + ":" + Base64.getEncoder().encodeToString(clientPublicKey.getEncoded());
            String certB64 = new ServerRequest(requestString).run();
            System.out.println(certB64);
            clientCertificate = loadCertificate(Base64.getDecoder().decode(certB64));
            System.out.println("Certificate requested from server");

            saveCertificate(clientCertificate, AppConfig.appProperties.getCertificatePath());
        }
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
            e.printStackTrace();
        }
        return kp;
    }


    public static void saveKey(byte [] key, String fileName) {
        try {
            FileOutputStream out = new FileOutputStream(fileName);
            out.write(key);
            out.close();
            System.out.println("Key saved to: " + fileName);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    public static PublicKey loadPublicKey(byte[] bytes) {
        PublicKey pub = null;
        try {
            X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            pub = kf.generatePublic(ks);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return pub;
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
            e.printStackTrace();
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
            e.printStackTrace();
        }
        return pvt;
    }


    private static void saveCertificate(X509Certificate cert, String filePath) {
        try {
            FileOutputStream out = new FileOutputStream(filePath);
            byte[] buf = cert.getEncoded();
            out.write(buf);
            out.close();
            System.out.println("Certificate saved to: " + filePath);
        } catch (IOException | CertificateEncodingException e) {
            e.printStackTrace();
        }
    }

    public static X509Certificate loadCertificate(byte[] bytes) {
        X509Certificate cert = null;
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            InputStream in = new ByteArrayInputStream(bytes);
            cert = (X509Certificate)certFactory.generateCertificate(in);
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        return cert;
    }

    public static X509Certificate loadCertificate(String filePath) {
        X509Certificate cert = null;
        try {
            Path path = Paths.get(filePath);
            byte[] bytes = Files.readAllBytes(path);

            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            InputStream in = new ByteArrayInputStream(bytes);

            cert = (X509Certificate)certFactory.generateCertificate(in);
        } catch (IOException | CertificateException e) {
            e.printStackTrace();
        }
        return cert;
    }


}
