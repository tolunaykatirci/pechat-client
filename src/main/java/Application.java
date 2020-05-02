import security.SecurityHelper;
import socket.MessageRequest;
import socket.SocketServer;
import util.AppConfig;
import util.CommunicationController;
import util.MenuThread;
import util.UserInputReader;

import java.util.Scanner;

public class Application {
    public static void main(String[] args) {
        // get application properties from file
        AppConfig.getApplicationProperties();

        // check server private/public key
        SecurityHelper.initialKeyPairCheck();

        // run socket server
        runSocketServer();

//        String serverPub = new ServerRequest("serverPub").run();
//        System.out.println(serverPub);

//        HandshakeRequestThread client = new HandshakeRequestThread();
//        new Thread(client).start();


        CommunicationController.reader = new UserInputReader();
        new Thread(CommunicationController.reader).start();

        //new PeFrame();
        System.out.println("Welcome to PeChat");
        MenuThread menu = new MenuThread();
        new Thread(menu).start();




    }

    private static void runSocketServer() {
        // run socket server on another thread
        SocketServer socketServer = new SocketServer(AppConfig.appProperties.getPort());
        Thread socketThread = new Thread(socketServer);
        socketThread.start();
    }

}
