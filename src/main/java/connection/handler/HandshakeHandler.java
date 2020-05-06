package connection.handler;

import lombok.Getter;
import security.CertificateManager;
import security.CipherManager;
import security.SecurityParameters;

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

@Getter
public class HandshakeHandler {
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

        System.out.println("[INFO] Peer Certificate Base64: " + peerCertificateB64);

        // get peer public key
        byte [] peerCertBytes = Base64.getDecoder().decode(peerCertificateB64);
        X509Certificate peerCertificate = CertificateManager.convertToCertificate(peerCertBytes);
        peerCertificate.verify(SecurityParameters.serverPublicKey);
        peerPublicKey = peerCertificate.getPublicKey();
        System.out.println("[INFO] Peer public key created");

        // create random number
        Random rnd = new Random();
        int nonce = rnd.nextInt(89)+10; // 10-99
        System.out.println("[INFO] Nonce generated: " + nonce);

        // send own certificate and random number
        String ownCert = Base64.getEncoder().encodeToString(SecurityParameters.ownCertificate.getEncoded());
        String nonceStr = nonce + ownCert;
        out.println(nonceStr);
        out.flush();
        System.out.println("[SENT] " + nonceStr);

        String signedNonce = in.readLine();
        System.out.println("[RECEIVED] " + signedNonce);


        assert CipherManager.verify(peerPublicKey, Integer.toString(nonce).getBytes(), Base64.getDecoder().decode(signedNonce));
        System.out.println("[INFO] Nonce verified. Public key is valid");

        // acknowledgement
        out.println("ack");
        out.flush();
        System.out.println("[SENT] ack");

        // encrypted master secret
        String peerEncryptedMasterSecretB64 = in.readLine();
        System.out.println("[RECEIVED] " + peerEncryptedMasterSecretB64 );

        peerMasterSecret = CipherManager.decrypt(SecurityParameters.ownPrivateKey, peerEncryptedMasterSecretB64);
        System.out.println("[INFO] Peer Master secret taken: " + peerMasterSecret);

        // encrypted master secret
        String ownEncryptedMasterSecretB64 = in.readLine();
        System.out.println("[RECEIVED] " + ownEncryptedMasterSecretB64 );

        ownMasterSecret = CipherManager.decrypt(SecurityParameters.ownPrivateKey, ownEncryptedMasterSecretB64);
        System.out.println("[INFO] Own Master secret taken: " + ownMasterSecret);

        System.out.println("[INFO] Handshake operation successful");
    }
}
