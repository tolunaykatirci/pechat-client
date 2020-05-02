package socket.handler;

import lombok.Getter;
import security.CipherHelper;
import security.SecurityHelper;

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
    private String masterSecret;

    public HandshakeHandler(BufferedReader in, PrintWriter out, String peerCertificateB64) {
        this.in = in;
        this.out = out;
        this.peerCertificateB64 = peerCertificateB64;
    }

    public void run() throws NoSuchProviderException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {

        System.out.println("[INFO] Peer Certificate Base64: " + peerCertificateB64);

        // get peer public key
        byte [] peerCertBytes = Base64.getDecoder().decode(peerCertificateB64);
        X509Certificate peerCertificate = SecurityHelper.loadCertificate(peerCertBytes);
        peerCertificate.verify(SecurityHelper.serverPublicKey);
        peerPublicKey = peerCertificate.getPublicKey();
        System.out.println("[INFO] Peer public key created");

        // create random number
        Random rnd = new Random();
        int nonce = rnd.nextInt(89)+10; // 10-99
        System.out.println("[INFO] Nonce generated: " + nonce);

        // send own certificate and random number
        String ownCert = Base64.getEncoder().encodeToString(SecurityHelper.clientCertificate.getEncoded());
        String nonceStr = nonce + ownCert;
        out.println(nonceStr);
        out.flush();
        System.out.println("[SENT] " + nonceStr);

        String signedNonce = in.readLine();
        System.out.println("[RECEIVED] " + signedNonce);


        assert CipherHelper.verify(peerPublicKey, Integer.toString(nonce).getBytes(), Base64.getDecoder().decode(signedNonce));
        System.out.println("[INFO] Nonce verified. Public key is valid");

        // acknowledgement
        out.println("ack");
        out.flush();
        System.out.println("[SENT] ack");

        // encrypted master secret
        String encryptedMasterSecretB64 = in.readLine();
        System.out.println("[RECEIVED] " + encryptedMasterSecretB64 );

        byte[] encryptedMasterSecret = Base64.getDecoder().decode(encryptedMasterSecretB64);
        masterSecret = CipherHelper.decrypt(SecurityHelper.clientPrivateKey, encryptedMasterSecret);
        System.out.println("[INFO] Master secret taken: " + masterSecret);

        System.out.println("[INFO] Handshake operation successful");
    }
}
