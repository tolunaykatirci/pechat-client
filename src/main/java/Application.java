import security.CertificateManager;
import security.KeyManager;
import socket.SocketServer;
import util.AppConfig;
import util.AppMenu;
import util.AppParameters;
import util.UserInputReader;

public class Application {
    public static void main(String[] args) {
        // get application properties from file
        AppConfig.getApplicationProperties();

        // check client private/public key
        boolean bool = KeyManager.initialKeyPairCheck();
        if (!bool)
            System.exit(-2);

        // check client certificate
        bool = CertificateManager.initialCertificateCheck();
        if (!bool)
            System.exit(-2);

        // run socket server
        runSocketServer();

        AppParameters.reader = new UserInputReader();
        new Thread(AppParameters.reader).start();

        AppMenu menu = new AppMenu("*** Welcome to PeChat ***");
        new Thread(menu).start();

    }

    private static void runSocketServer() {
        // run socket server on another thread
        SocketServer socketServer = new SocketServer(AppConfig.appProperties.getPort());
        Thread socketThread = new Thread(socketServer);
        socketThread.start();
    }

}
