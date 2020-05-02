package socket;

import util.CommunicationController;

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

            System.out.println("Client IP: " + clientSocket.getLocalAddress());

            String line = in.readLine();

            // parse request
            parse(line, clientSocket.getLocalAddress().toString());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void parse(String allData, String ip) throws IOException {
        if (allData.startsWith("hello")) {
            // register a new client
            try {
                String clientCert = allData.substring(5);

                if (!CommunicationController.inCommunication){
                    // handle request in background
                    System.out.println("[RECEIVED] " + allData);
                    new Thread(new MessageHandler(clientSocket, in, out, clientCert)).start();
                } else {
                    // in another communication
                    respond("busy");
                }
            } catch (Exception e) {
                e.printStackTrace();
                respond("error");
            }
        }
    }

    private void respond(String res) throws IOException {
        out.write(res);
        out.flush();
        out.close();
        // close close
        clientSocket.close();
    }
}
