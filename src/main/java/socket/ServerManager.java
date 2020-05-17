package socket;

import security.SecurityParameters;
import util.AppConfig;
import util.PeerModel;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.logging.Logger;

public class ServerManager {

    private static Logger log = AppConfig.getLogger(ServerManager.class.getName());

    public static String getServerPublicKey(){
        String serverPublicKeyB64 = null;
        try {
            // open socket
            Socket clientSocket = new Socket(AppConfig.appProperties.getServerIp(), AppConfig.appProperties.getServerPort());
            BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            PrintWriter out  = new PrintWriter(clientSocket.getOutputStream(), true);

            out.println("serverPub");
            out.flush();
            log.info("[SENT] serverPub");

            String response = in.readLine();
            log.info("[RECEIVED] " + response);

            if (response.equals("error"))
                return null;

            serverPublicKeyB64 = response;
            // close connections
            in.close();
            out.close();
            clientSocket.close();

        } catch (Exception e) {
            log.warning(e.getMessage());
        }
        return serverPublicKeyB64;
    }

    public static String register(){
        String certificateB64 = null;
        try {
            // open socket
            Socket clientSocket = new Socket(AppConfig.appProperties.getServerIp(), AppConfig.appProperties.getServerPort());
            BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            PrintWriter out  = new PrintWriter(clientSocket.getOutputStream(), true);

            // register: register as client (register:userName:port:clientPublicKey) returns certificate

            String request = "register:"
                    + AppConfig.appProperties.getUserName() + ":"
                    + AppConfig.appProperties.getPort() + ":"
                    + Base64.getEncoder().encodeToString(SecurityParameters.ownPublicKey.getEncoded());

            out.println(request);
            out.flush();
            log.info("[SENT] " + request);

            String response = in.readLine();
            log.info("[RECEIVED] " + response);

            if (response.equals("error"))
                return null;

            certificateB64 = response;

            // close connections
            in.close();
            out.close();
            clientSocket.close();

        } catch (Exception e) {
            log.warning(e.getMessage());
        }
        return certificateB64;
    }

    public static List<PeerModel> getPeers(){
        List<PeerModel> peers = new ArrayList<>();
        try {
            // open socket
            Socket clientSocket = new Socket(AppConfig.appProperties.getServerIp(), AppConfig.appProperties.getServerPort());
            BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            PrintWriter out  = new PrintWriter(clientSocket.getOutputStream(), true);

            // list: get all clients (list:clientCert) returns list

            String request = "list:"
                    + Base64.getEncoder().encodeToString(SecurityParameters.ownCertificate.getEncoded());

            out.println(request);
            out.flush();
            log.info("[SENT] " + request);

            String response = in.readLine();
            log.info("[RECEIVED] " + response);

            if (response.equals("error"))
                return null;


            while (response != null && !response.equals("end")) {
                String [] params = response.split(":");

                PeerModel peer = new PeerModel();
                peer.setUserName(params[0]);
                peer.setIp(params[1]);
                peer.setPort(Integer.parseInt(params[2]));

                // add to list if not himself / herself
                if (!peer.getUserName().equals(AppConfig.appProperties.getUserName()))
                    peers.add(peer);

                response = in.readLine();
                log.info("[RECEIVED] " + response);
            }

            // close connections
            in.close();
            out.close();
            clientSocket.close();

        } catch (Exception e) {
            log.warning(e.getMessage());
        }
        return peers;
    }
}
