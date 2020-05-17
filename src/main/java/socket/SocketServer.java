package socket;

import util.AppConfig;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.logging.Logger;

public class SocketServer implements Runnable{

    private static Logger log = AppConfig.getLogger(SocketServer.class.getName());

    private int serverPort;
    private ServerSocket serverSocket = null;
    private boolean isStopped = false;
    private Thread runningThread = null;

    // constructor
    public SocketServer(int serverPort) {
        this.serverPort = serverPort;
    }

    @Override
    public void run() {
        // run multithread
        synchronized (this) {
            this.runningThread = Thread.currentThread();
        }

        // open socket server
        openServerSocket();

        while (!isStopped) {
            Socket clientSocket = null;
            try {
                // accept request and send to handler
                clientSocket = this.serverSocket.accept();
            } catch (IOException e) {
                if(isStopped()) {
                    log.info("[INFO] Server Stopped.");
                    return;
                }
                throw new RuntimeException("[ERROR] Error accepting client connection", e);
            }

            // handle request in background
            new Thread(new ClientHandler(clientSocket)).start();
        }
    }

    // stop socket server
    public synchronized void stop(){
        this.isStopped = true;
        try {
            this.serverSocket.close();
        } catch (IOException e) {
            throw new RuntimeException("[ERROR] Error closing server", e);
        }
    }

    private synchronized boolean isStopped() {
        return this.isStopped;
    }

    // start socket server
    private void openServerSocket() {
        try {
            this.serverSocket = new ServerSocket(this.serverPort);
            log.info("Server started at port: " + this.serverPort);
        } catch (IOException e) {
            throw new RuntimeException("[ERROR] Cannot open port "+ this.serverPort, e);
        }
    }
}
