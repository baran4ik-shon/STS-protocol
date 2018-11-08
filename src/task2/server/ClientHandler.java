package task2.server;

import task2.sts.STSImplementation;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.Base64;


public class ClientHandler implements Runnable {
    private Socket socket;
    private BufferedReader in;
    private STSImplementation dh;

    public ClientHandler(Socket socket) {
        this.socket = socket;
        dh = new STSImplementation();
        try {
            in = new BufferedReader(new InputStreamReader(this.socket.getInputStream()));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    private void log(String s) {
        System.out.println(s);
    }

    public void run() {
        String line;
        try {
            dh.startSTSagreement(in, new PrintWriter(socket.getOutputStream()));

            while ((line = in.readLine()) != null) {
                log("Alice" + " : " + new String(dh.decrypt(Base64.getDecoder().decode(line))));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
