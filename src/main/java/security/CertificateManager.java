package security;

import socket.ServerManager;
import util.AppConfig;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class CertificateManager {


    public static boolean initialCertificateCheck() {
        File certFile = new File(AppConfig.appProperties.getCertificatePath());
        if(certFile.exists()){
            // load certificate
            SecurityParameters.ownCertificate = loadCertificate(AppConfig.appProperties.getCertificatePath());
            System.out.println("[INFO] Certificate loaded from file");
        } else {
            // get certificate from server
            String certificateB64 = ServerManager.register();
            if (certificateB64 != null){
                SecurityParameters.ownCertificate = convertToCertificate(Base64.getDecoder().decode(certificateB64));
                System.out.println("[INFO] Registered to server");
                saveCertificate(SecurityParameters.ownCertificate, AppConfig.appProperties.getCertificatePath());
            } else {
                System.out.println("[ERROR] Could not register to server");
                return false;
            }
        }
        return true;
    }

    public static void saveCertificate(X509Certificate cert, String filePath) {
        try {
            FileOutputStream out = new FileOutputStream(filePath);
            byte[] buf = cert.getEncoded();
            out.write(buf);
            out.close();
            System.out.println("[INFO] Certificate saved to: " + filePath);
        } catch (IOException | CertificateEncodingException e) {
            e.printStackTrace();
        }
    }

    public static X509Certificate convertToCertificate(byte[] bytes) {
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
