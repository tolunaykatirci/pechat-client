package connection.request;

import lombok.Getter;
import security.CertificateManager;
import security.CipherManager;
import security.KeyManager;
import security.SecurityParameters;
import util.AppConfig;
import util.AppParameters;

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
import java.util.logging.Logger;

@Getter
public class HandshakeRequest {

    private static Logger log = AppConfig.getLogger(HandshakeRequest.class.getName());

    private BufferedReader in;
    private PrintWriter out;

    private String peerCertificateB64;
    private PublicKey peerPublicKey;
    private String ownMasterSecret;
    private String peerMasterSecret;

    public HandshakeRequest(BufferedReader in, PrintWriter out) {
        this.in = in;
        this.out = out;
    }

    public int run() throws CertificateException, IOException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {

        /* return
         *  0: okay
         *  -1: error
         *  -2: busy
         */

        String ownCertificate = Base64.getEncoder().encodeToString(SecurityParameters.ownCertificate.getEncoded());

        //out.write("hello"+ownCertificate);
        String helloMessage = "hello:" + AppConfig.appProperties.getUserName() + ":" + ownCertificate;
        out.println(helloMessage);
        out.flush();
        log.info("[SENT]" + helloMessage);

        String response = in.readLine();
        log.info("[RECEIVED] " + response);

        if (response.equals("error")){
            return -1;
        } else if (response.equals("busy")){
            return -2;
        }

        String[] splt = response.split(":");
        String nonce = splt[0];   // random number
        peerCertificateB64 = splt[1];  // peer certificate Base64
        log.info("Nonce: " + nonce);
        log.info("Peer Certificate Base64: " + peerCertificateB64);

        // get peer public key
        byte [] peerCertBytes = Base64.getDecoder().decode(peerCertificateB64);
        X509Certificate peerCertificate = CertificateManager.convertToCertificate(peerCertBytes);
        peerCertificate.verify(SecurityParameters.serverPublicKey);
        log.info("Peer certificate verified");
        peerPublicKey = peerCertificate.getPublicKey();
        log.info("Peer public key created");

        // sign nonce with
        String signatureB64 = CipherManager.sign(SecurityParameters.ownPrivateKey, nonce);
        log.info("Nonce signed");

        // send signed nonce to peer
        out.println(signatureB64);
        out.flush();
        log.info("[SENT]" + signatureB64);

        // get response
        String ackB64 = in.readLine();
        log.info("[RECEIVED] " + ackB64);
        String ack = CipherManager.decrypt(SecurityParameters.ownPrivateKey, ackB64);

        // if ack is wrong, create exception
        assert ack != null;
        assert !ack.equals("acknowledgement");
        log.info("acknowledgement successfully verified");

        // Generating Keys.
        ownMasterSecret = KeyManager.generateMasterSecret();
        log.info("Own Master secret generated: " + ownMasterSecret);
        String encryptedMasterSecretB64 = CipherManager.encrypt(peerPublicKey, ownMasterSecret);
        log.info("Own Master secret encrypted with peer public key");

        out.println(encryptedMasterSecretB64);
        out.flush();
        log.info("[SENT]" + encryptedMasterSecretB64);

        // Same operation for peer master secret
        peerMasterSecret = KeyManager.generateMasterSecret();
        log.info("Peer Master secret generated: " + peerMasterSecret);

        String peerEncryptedMasterSecretB64 = CipherManager.encrypt(peerPublicKey, peerMasterSecret);
        log.info("Peer Master secret encrypted with peer public key");

        out.println(peerEncryptedMasterSecretB64);
        out.flush();
        log.info("[SENT]" + peerEncryptedMasterSecretB64);


        String handshakeFinishedEncryptedB64 = in.readLine();
        log.info("[RECEIVED]" + handshakeFinishedEncryptedB64);
        String hf = CipherManager.decrypt(SecurityParameters.ownPrivateKey, handshakeFinishedEncryptedB64);

        assert hf != null;
        assert !hf.equals("handshakeFinished");
        log.info("Handshake finish operation came from peer");

        String handshakeFinished = "handshakeFinished";
        String handshakeFinishedEncrypted = CipherManager.encrypt(peerPublicKey, handshakeFinished);
        out.println(handshakeFinishedEncrypted);
        out.flush();
        log.info("[SENT] " + handshakeFinishedEncrypted);

        log.info("Handshake operation successful");

        return 0;
    }




}
