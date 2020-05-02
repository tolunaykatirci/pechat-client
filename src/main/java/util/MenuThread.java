package util;

import socket.MessageRequest;

import java.util.Scanner;

public class MenuThread implements Runnable {


    public MenuThread() {
    }

    @Override
    public void run() {
        System.out.println("Select an operation");
        System.out.println("1. Start Chat");
        System.out.println("2. Exit");

        // thread closed
        while (!CommunicationController.inCommunication) {

            if (CommunicationController.reader != null && CommunicationController.reader.isReady()) {
                String userInput = CommunicationController.reader.readLine();
                System.out.println("[INFO] Menu input: "+userInput);
                int option;
                try {
                    option = Integer.parseInt(userInput);
                } catch (Exception e) {
                    e.printStackTrace();
                    continue;
                }

                if (option == 1) {
                    MessageRequest client = new MessageRequest();
                    new Thread(client).start();
                } else if (option == 2) {
                    System.exit(400);
                }
            } else {
                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        }
        System.out.println("[INFO] Menu thread interrupted");
    }
}
