package socket;

import connection.handler.MessageHandler;
import util.AppConfig;
import util.AppParameters;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.logging.Logger;

public class ClientHandler implements Runnable {

    private static Logger log = AppConfig.getLogger(ClientHandler.class.getName());

    private Socket clientSocket;
    private BufferedReader in;
    private PrintWriter out;

    // constructor
    public ClientHandler(Socket clientSocket) {
        this.clientSocket = clientSocket;
    }

    @Override
    public void run() {
        try {
            in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            out = new PrintWriter(clientSocket.getOutputStream(), true);

            log.info("Client IP: " + clientSocket.getLocalAddress().getHostAddress());

            String line = in.readLine();

            // parse request
            parse(line);

        } catch (Exception e) {
            log.warning(e.getMessage());
        }
    }

    private void parse(String allData) throws IOException {
        if (allData.startsWith("hello")) {
            // register a new client
            try {
                String[] splitted = allData.split(":");

                String peerUserName = splitted[1];
                String peerCert = splitted[2];

                if (!AppParameters.inCommunication){
                    // handle request in background
                    log.info("[RECEIVED] " + allData);
                    new Thread(new MessageHandler(clientSocket, in, out, peerUserName, peerCert)).start();
                } else {
                    // in another communication
                    respond("busy");
                    log.info("[SENT] busy");
                }
            } catch (Exception e) {
                log.warning(e.getMessage());
                respond("error");
                log.info("[SENT] error");
            }
        } else {
            // unexpected message
            log.warning("Unexpected request");
            respond("error");
            log.info("[SENT] error");
        }
    }

    private void respond(String res) throws IOException {
        out.println(res);
        out.flush();
        out.close();
        // close close
        clientSocket.close();
    }
}
