package util;

import connection.request.MessageRequest;
import socket.ServerManager;

import java.util.List;

public class AppMenu implements Runnable {


    public AppMenu(String initialMessage) {
        if (initialMessage != null)
            System.out.println(initialMessage);
    }

    @Override
    public void run() {
        System.out.println("Select an operation");
        System.out.println("1. List users");
        System.out.println("2. Exit");

        int input = getInput(2);
        if (input == -1){
            // menu interrupted
            System.out.println("[INFO] Menu thread interrupted");
        } else if (input == 1){
            System.out.println("Select a user to chat");
            List<PeerModel> peers = ServerManager.getPeers();

            if (peers==null || peers.size() == 0) {
                System.out.println("[ERROR] Could not get any user from server");
                System.exit(-2);
            }

            for (int i = 0; i < peers.size(); i++) {
                System.out.println((i+1) + ". " + peers.get(i).getUserName());
            }
            System.out.println((peers.size()+1) + ". Return to menu");
            input = getInput(peers.size()+1);
            if (input == -1){
                // menu interrupted
                System.out.println("[INFO] Menu thread interrupted");
            } else if (input == peers.size()+1) {
                // return to menu
                AppMenu menu = new AppMenu(null);
                new Thread(menu).start();
            }
            else {
                PeerModel selectedPeer = peers.get(input-1);
                MessageRequest mr = new MessageRequest(selectedPeer);
                mr.run();
            }
        } else {
            System.out.println("GoodBye!");
            System.exit(1);
        }
    }

    private int getInput(int range) {
        int input = -1;
        while (!AppParameters.inCommunication) {
            if (AppParameters.reader != null && AppParameters.reader.isReady()) {
                String userInput = AppParameters.reader.readLine();
                System.out.println("[INFO] Menu input: "+userInput);
                int option;
                try {
                    option = Integer.parseInt(userInput);
                } catch (Exception e) {
                    e.printStackTrace();
                    System.out.println("Please enter only integer!");
                    continue;
                }
                if (option < 1 || option > range) {
                        System.out.println("Please enter only 1-" + range);
                    continue;
                }
                input = option;
                break;
            } else {
                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        }
        return input;
    }
}
