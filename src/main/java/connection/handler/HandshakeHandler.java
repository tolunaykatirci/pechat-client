package connection.handler;

import lombok.Getter;
import security.CertificateManager;
import security.CipherManager;
import security.SecurityParameters;
import util.AppConfig;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Random;
import java.util.logging.Logger;

@Getter
public class HandshakeHandler {

    private static Logger log = AppConfig.getLogger(HandshakeHandler.class.getName());

    private BufferedReader in;
    private PrintWriter out;

    private String peerCertificateB64;
    private PublicKey peerPublicKey;

    private String ownMasterSecret;
    private String peerMasterSecret;

    public HandshakeHandler(BufferedReader in, PrintWriter out, String peerCertificateB64) {
        this.in = in;
        this.out = out;
        this.peerCertificateB64 = peerCertificateB64;
    }

    public void run() throws NoSuchProviderException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {

        log.info("Peer Certificate Base64: " + peerCertificateB64);

        // get peer public key
        byte [] peerCertBytes = Base64.getDecoder().decode(peerCertificateB64);
        X509Certificate peerCertificate = CertificateManager.convertToCertificate(peerCertBytes);
        peerCertificate.verify(SecurityParameters.serverPublicKey);
        log.info("Peer certificate verified");
        peerPublicKey = peerCertificate.getPublicKey();
        log.info("Peer public key created");

        // create random number
        Random rnd = new Random();
        long nonce1 = rnd.nextLong();
        long nonce2 = rnd.nextLong();
        String nonce = nonce1 + String.valueOf(nonce2);
        log.info("Nonce generated: " + nonce);

        // send own certificate and random number
        String ownCert = Base64.getEncoder().encodeToString(SecurityParameters.ownCertificate.getEncoded());
        String nonceStr = nonce + ":" + ownCert;
        out.println(nonceStr);
        out.flush();
        log.info("[SENT] " + nonceStr);

        String signedNonce = in.readLine();
        log.info("[RECEIVED] " + signedNonce);


        assert CipherManager.verify(peerPublicKey, nonce.getBytes(), Base64.getDecoder().decode(signedNonce));
        log.info("Nonce verified. Public key is valid");

        // acknowledgement
        String ackEncrypted = CipherManager.encrypt(peerPublicKey, "acknowledgement");
        out.println(ackEncrypted);
        out.flush();
        log.info("[SENT] " + ackEncrypted);
        log.info("Encrypted acknowledgement sent");

        // encrypted master secret
        String peerEncryptedMasterSecretB64 = in.readLine();
        log.info("[RECEIVED]" + peerEncryptedMasterSecretB64);

        peerMasterSecret = CipherManager.decrypt(SecurityParameters.ownPrivateKey, peerEncryptedMasterSecretB64);
        log.info("Peer Master secret taken: " + peerMasterSecret);

        // encrypted master secret
        String ownEncryptedMasterSecretB64 = in.readLine();
        log.info("[RECEIVED]" + ownEncryptedMasterSecretB64);

        ownMasterSecret = CipherManager.decrypt(SecurityParameters.ownPrivateKey, ownEncryptedMasterSecretB64);
        log.info("Own Master secret taken: " + ownMasterSecret);

        String handshakeFinished = "handshakeFinished";
        String handshakeFinishedEncrypted = CipherManager.encrypt(peerPublicKey, handshakeFinished);
        out.println(handshakeFinishedEncrypted);
        out.flush();
        log.info("[SENT] " + handshakeFinishedEncrypted);

        String handshakeFinishedEncryptedB64 = in.readLine();
        log.info("[RECEIVED]" + handshakeFinishedEncryptedB64);
        String hf = CipherManager.decrypt(SecurityParameters.ownPrivateKey, handshakeFinishedEncryptedB64);
        assert hf != null;
        assert !hf.equals("handshakeFinished");
        log.info("Handshake finish operation came from peer");

        log.info("Handshake operation successful");
    }
}
