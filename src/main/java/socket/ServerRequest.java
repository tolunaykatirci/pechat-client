package socket;

import util.AppConfig;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.PublicKey;

public class ServerRequest {

    private Socket clientSocket = null;
    private String ip;
    private int port;
    private String request;

    public ServerRequest(String request) {
        this.ip = AppConfig.appProperties.getServerIp();
        this.port = AppConfig.appProperties.getServerPort();
        this.request = request;
    }

    public String run() {
        String response = null;
        try {
            // open socket
            Socket clientSocket = new Socket(ip,port);
            BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            PrintWriter out  = new PrintWriter(clientSocket.getOutputStream(), true);

            System.out.println(request);
            out.println(request);
            out.flush();

            response = in.readLine();

            // close connections
            in.close();
            out.close();
            clientSocket.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
        return response;
    }
}
