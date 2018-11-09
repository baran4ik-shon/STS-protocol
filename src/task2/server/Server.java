package task2.server;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;


public class Server {

    public static void main(String[] args) throws IOException {
        int port = 7777;
        ServerSocket server = new ServerSocket(port);
        Socket socket = server.accept();
        new Thread(new ClientHandler(socket)).start();
    }
}
