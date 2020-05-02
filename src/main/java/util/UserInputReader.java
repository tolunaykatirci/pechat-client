package util;

import lombok.Getter;

import java.util.Scanner;

public class UserInputReader implements Runnable{

    private volatile String input;
    private volatile boolean ready = false;
    private Scanner scanner;

    public UserInputReader() {
        scanner = new Scanner(System.in);
    }

    public synchronized boolean isReady(){
        return ready;
    }

    public synchronized String readLine(){
        ready = false;
        return input;
    }

    @Override
    public void run() {
        while (true) {
            input = scanner.nextLine();
            ready = true;
        }
    }
}
