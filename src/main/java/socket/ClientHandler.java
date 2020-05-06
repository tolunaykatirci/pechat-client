package socket;

import connection.handler.MessageHandler;
import util.AppParameters;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

public class ClientHandler implements Runnable {

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

            System.out.println("Client IP: " + clientSocket.getLocalAddress().getHostAddress());

            String line = in.readLine();

            // parse request
            parse(line);

        } catch (Exception e) {
            e.printStackTrace();
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
                    System.out.println("[RECEIVED] " + allData);
                    new Thread(new MessageHandler(clientSocket, in, out, peerUserName, peerCert)).start();
                } else {
                    // in another communication
                    respond("busy");
                    System.out.println("[SENT] busy");
                }
            } catch (Exception e) {
                e.printStackTrace();
                respond("error");
                System.out.println("[SENT] error");
            }
        } else {
            // unexpected message
            System.out.println("[INFO] unexpected request");
            respond("error");
            System.out.println("[SENT] error");
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
