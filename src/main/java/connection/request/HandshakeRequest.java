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

@Getter
public class HandshakeRequest {

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
        System.out.println("[SENT] " + helloMessage);

        String response = in.readLine();
        System.out.println("[RECEIVED] " + response);

        if (response.equals("error")){
            return -1;
        } else if (response.equals("busy")){
            return -2;
        }

        String nonce = response.substring(0, 2);    // random number
        peerCertificateB64 = response.substring(2);  // peer certificate Base64
        System.out.println("[INFO] Nonce: " + nonce);
        System.out.println("[INFO] Peer Certificate Base64: " + peerCertificateB64);

        // get peer public key
        byte [] peerCertBytes = Base64.getDecoder().decode(peerCertificateB64);
        X509Certificate peerCertificate = CertificateManager.convertToCertificate(peerCertBytes);
        peerCertificate.verify(SecurityParameters.serverPublicKey);
        peerPublicKey = peerCertificate.getPublicKey();
        System.out.println("[INFO] Peer public key created");

        // sign nonce with
        String signatureB64 = CipherManager.sign(SecurityParameters.ownPrivateKey, nonce);
        System.out.println("[INFO] Nonce signed");

        // send signed nonce to peer
        out.println(signatureB64);
        out.flush();
        System.out.println("[SENT] " + signatureB64);

        // get response
        String ack = in.readLine();
        System.out.println("[RECEIVED] " + ack);

        // if ack is wrong, create exception
        assert !ack.equals("ack");

        // Generating Keys.
        ownMasterSecret = KeyManager.generateMasterSecret();
        System.out.println("[INFO] Own Master secret generated: " + ownMasterSecret);
        String encryptedMasterSecretB64 = CipherManager.encrypt(peerPublicKey, ownMasterSecret);
        System.out.println("[INFO] Own Master secret encrypted with peer public key");

        out.println(encryptedMasterSecretB64);
        out.flush();
        System.out.println("[SENT] " + encryptedMasterSecretB64);

        // Same operation for peer master secret
        peerMasterSecret = KeyManager.generateMasterSecret();
        System.out.println("[INFO] Peer Master secret generated: " + peerMasterSecret);

        String peerEncryptedMasterSecretB64 = CipherManager.encrypt(peerPublicKey, peerMasterSecret);
        System.out.println("[INFO] Peer Master secret encrypted with peer public key");

        out.println(peerEncryptedMasterSecretB64);
        out.flush();
        System.out.println("[SENT] " + peerEncryptedMasterSecretB64);

        System.out.println("[INFO] Handshake operation successful");

        return 0;
    }




}
