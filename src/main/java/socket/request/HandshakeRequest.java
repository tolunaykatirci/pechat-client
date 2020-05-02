package socket.request;

import lombok.Getter;
import security.CipherHelper;
import security.SecurityHelper;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;

@Getter
public class HandshakeRequest {

    private BufferedReader in;
    private PrintWriter out;

    private String peerCertificateB64;
    private PublicKey peerPublicKey;
    private String masterSecret;

    public HandshakeRequest(BufferedReader in, PrintWriter out) {
        this.in = in;
        this.out = out;
    }

    public void run() throws CertificateException, IOException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
        String ownCertificate = Base64.getEncoder().encodeToString(SecurityHelper.clientCertificate.getEncoded());

        //out.write("hello"+ownCertificate);
        out.println("hello" + ownCertificate);
        out.flush();
        System.out.println("[SENT] " + "hello" + ownCertificate);


        String response = in.readLine();
        System.out.println("[RECEIVED] " + response);

        String nonce = response.substring(0, 2);    // random number
        peerCertificateB64 = response.substring(2);  // peer certificate Base64
        System.out.println("[INFO] Nonce: " + nonce);
        System.out.println("[INFO] Peer Certificate Base64: " + peerCertificateB64);

        // get peer public key
        byte [] peerCertBytes = Base64.getDecoder().decode(peerCertificateB64);
        X509Certificate peerCertificate = SecurityHelper.loadCertificate(peerCertBytes);
        peerCertificate.verify(SecurityHelper.serverPublicKey);
        peerPublicKey = peerCertificate.getPublicKey();
        System.out.println("[INFO] Peer public key created");

        // sign nonce with
        byte[] signature = CipherHelper.sign(SecurityHelper.clientPrivateKey, nonce);
        System.out.println("[INFO] Nonce signed");

        // send signed nonce to peer
        String signatureB64 = Base64.getEncoder().encodeToString(signature);
        out.println(signatureB64);
        out.flush();
        System.out.println("[SENT] " + signatureB64);

        // get response
        String ack = in.readLine();
        System.out.println("[RECEIVED] " + ack);

        // if ack is wrong, create exception
        assert !ack.equals("ack");

        // Generating IV.
        byte[] iv = CipherHelper.generateRandomBytes(16);
        byte[] macSecret = CipherHelper.generateRandomBytes(32);
        byte[] aesSecret = CipherHelper.generateRandomBytes(128);

        masterSecret = Base64.getEncoder().encodeToString(iv)
                + ":" + Base64.getEncoder().encodeToString(macSecret)
                + ":" + Base64.getEncoder().encodeToString(aesSecret);
        System.out.println("[INFO] Master secret generated: " + masterSecret);

        byte[] encryptedMasterSecret = CipherHelper.encrypt(peerPublicKey, masterSecret);
        String encryptedMasterSecretB64 = Base64.getEncoder().encodeToString(encryptedMasterSecret);
        System.out.println("[INFO] Master secret encrypted with peer public key");

        out.println(encryptedMasterSecretB64);
        out.flush();
        System.out.println("[SENT] " + encryptedMasterSecretB64);

        System.out.println("[INFO] Handshake operation successful");
    }




}
