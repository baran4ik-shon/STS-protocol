package task2.server;

import task2.sts.STSImplementation;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.Base64;

import static java.lang.System.out;


public class ClientHandler implements Runnable {
    private Socket socket;
    private BufferedReader in;

    private STSImplementation dh;

    ClientHandler(Socket socket) {
        this.socket = socket;
        dh = new STSImplementation();
        try {
            in = new BufferedReader(new InputStreamReader(this.socket.getInputStream()));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void run() {
        try {
            dh.startSTSAgreement(in, new PrintWriter(socket.getOutputStream()));
        } catch (IOException e) {
            e.printStackTrace();
        }
        // send message to Alice
        new Thread(() -> {
            String line;
            BufferedReader in =
                    new BufferedReader(new InputStreamReader(System.in));
            try {
                PrintWriter out = new PrintWriter(socket.getOutputStream());
                while((line = in.readLine()) != null){
                    line =  Base64.getEncoder().encodeToString(dh.encrypt(line.getBytes()));
                    out.println(line);
                    out.flush();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }).start();

        // reading message
        try {
        String line;
            while ((line = in.readLine()) != null) {
                log("Alice" + " : " + new String(dh.decrypt(Base64.getDecoder().decode(line))));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    private void log(String s) {
        out.println(s);
    }
}
