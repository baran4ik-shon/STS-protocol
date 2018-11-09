package task2.client;

import task2.sts.STSImplementation;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.Base64;

import static java.lang.System.out;


public class Client {

    public static void main(String[] args) throws IOException {
        String host = "localhost";
        int port = 7777;
        Socket socket = new Socket(host, port);
        STSImplementation dh = new STSImplementation();
        BufferedReader in =
                new BufferedReader(new InputStreamReader(System.in));
        PrintWriter out = new PrintWriter(socket.getOutputStream());
        BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        // verify
        dh.proceedSTSAgreement(new BufferedReader(new InputStreamReader(socket.getInputStream())), out);

        // Bob's message reading
        new Thread(() -> {
            String line1;
            try {
                while ((line1 = input.readLine()) != null) {
                    log("Bob" + " : " + new String(dh.decrypt(Base64.getDecoder().decode(line1))));
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }).start();

        // send message to Alice
        String line;
        while((line = in.readLine()) != null){
            line =  Base64.getEncoder().encodeToString(dh.encrypt(line.getBytes()));
            out.println(line);
            out.flush();
        }
        socket.shutdownInput();
        socket.shutdownOutput();
        socket.close();

    }

    private static void log(String s) {
        out.println(s);
    }

}
