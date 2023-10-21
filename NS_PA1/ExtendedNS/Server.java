package ExtendedNS;
import java.lang.*;
import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.CountDownLatch;

import javax.crypto.*;
import java.security.*;


// import expandedNeedhamSchroederMaster.protocols.Protocol;
// import expandedNeedhamSchroederMaster.tcp.TcpObject;
// import expandedNeedhamSchroederMaster.util.Util;



abstract public class Server extends ServerObject implements Runnable {
  
  CountDownLatch latch;


  abstract List<Object> getServerMsg(List<Object> listOfMessages);
  abstract CountDownLatch getLatch();


  public void run() {
Integer serverPort=getPort();

latch=getLatch();

  ServerSocket serverSocket = null; 
  Socket clientSocket = null;
  PrintWriter out = null;
  BufferedReader in = null;

  try {
    
    while(true){
    serverSocket = new ServerSocket(serverPort);
    // Start accepting connections
      clientSocket = serverSocket.accept();
      ObjectInputStream objectInputStream = new ObjectInputStream(clientSocket.getInputStream());

            List<Object> listOfMessages = (List<Object>) objectInputStream.readObject();

       // Will call Bob's getServerMsg if Bob thread is running or will call KDC's getServerMsg if KDC thread is running.
            List<Object> serverMessageOut= getServerMsg(listOfMessages);
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(clientSocket.getOutputStream());
            objectOutputStream.writeObject(serverMessageOut);

          // Close the sockets and streams
            clientSocket.close();
      objectInputStream.close();
      objectOutputStream.close();
      serverSocket.close();
    }
            // latch.countDown();

          //   try {
          //     latch.await();
          // } catch (InterruptedException e) {
          //     // Handle exception
          // }
          
         
          
      
        
    
  }
  catch(Exception e) {
    System.out.println("Server start failed!!!");
    System.out.println(e.getMessage());
    System.out.println(e.getClass());  
    // cleanUp(serverSocket, clientSocket, out, in);
  }

}


}


    


