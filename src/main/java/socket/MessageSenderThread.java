package socket;

import lombok.Getter;
import util.CommunicationController;

import java.io.PrintWriter;
import java.util.Scanner;

@Getter
public class MessageSenderThread implements Runnable {

    private PrintWriter out;
    private volatile boolean exit = false;
    private Message m;

    public MessageSenderThread(Message m, PrintWriter out) {
        CommunicationController.inCommunication = true;
        this.out = out;
        this.m = m;
    }

    @Override
    public void run() {

        while (CommunicationController.inCommunication){
            if(CommunicationController.reader.isReady()){
                String message = CommunicationController.reader.readLine();
                if (message.equals("!exit")){
                    out.println(message);
                    out.flush();
                    m.closeConnection();
                    // todo stop islemi nasil olacak
//                    stop();
                } else {
                    out.println(message);
                    out.flush();
                }
            }
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }

        }
    }

    public void stop(){
        exit = true;
    }
}
