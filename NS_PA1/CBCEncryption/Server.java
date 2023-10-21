package CBCEncryption;
import java.lang.*;
import java.io.*;
import java.net.*;
import java.util.*;

import javax.crypto.*;
import java.security.*;



//This class extends ServerObject and implements Runnable

abstract public class Server extends ServerObject implements Runnable {
  
  abstract List<Object> getServerMsg(List<Object> listOfMessages);


  public void run() {
Integer serverPort=getPort();



  ServerSocket serverSocket = null; 
  Socket clientSocket = null;
  PrintWriter out = null;
  BufferedReader in = null;

  try {
    serverSocket = new ServerSocket(serverPort);
    // Start accepting connections
      clientSocket = serverSocket.accept();
      ObjectInputStream objectInputStream = new ObjectInputStream(clientSocket.getInputStream());

            List<Object> listOfMessages = (List<Object>) objectInputStream.readObject();

             // Will call Bob's getServerMsg if Bob thread is running or will call KDC's getServerMsg if KDC thread is running.
            List<Object> serverMessageOut= getServerMsg(listOfMessages);
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(clientSocket.getOutputStream());
            objectOutputStream.writeObject(serverMessageOut);
      
      // Closing all the resources.      
      clientSocket.close();
      objectInputStream.close();
      objectOutputStream.close();
      serverSocket.close();

    
  }
  catch(Exception e) {
    System.out.println("Server start failed!!!");
    System.out.println(e.getMessage());
    System.out.println(e.getClass());  
    // cleanUp(serverSocket, clientSocket, out, in);
  }

}


}


    


