package connection;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.BufferedReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.PublicKey;

public interface Message {

    void closeConnection(String message);
}
