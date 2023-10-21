
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;

import java.util.*;
import java.io.*;


public class CA implements Runnable{

  public static Integer PORT = 8899;


    //Getting port number of KDC
    public Integer getPort() {
        return PORT;
      }


public void run()
{

  ServerSocket serverSocket;
  Socket clientSocket;
  while(true)
  {
  try {
    serverSocket = new ServerSocket(8899);


         clientSocket = serverSocket.accept();
        // System.out.println("Client connected: " + clientSocket);
        ObjectInputStream objectInputStream = new ObjectInputStream(clientSocket.getInputStream());

            List<Object> listOfMessages = (List<Object>) objectInputStream.readObject();
            //Sending the certificate to either Bob or Alice based on the request CA recieves 
            if(listOfMessages.get(0).equals("I am Bob and I want a certificate")||listOfMessages.get(0).equals("I am Alice and I want a certificate"))
            {
              getMsg1(listOfMessages, clientSocket);
            }
             serverSocket.close();
             clientSocket.close();

  } catch (IOException e) {
    // TODO Auto-generated catch block
    e.printStackTrace();
  } catch (ClassNotFoundException e) {
    // TODO Auto-generated catch block
    e.printStackTrace();
  }
  
  }
  
  
}
 
    List<Object> getMsg1(List<Object> listOfMessages, Socket clientSocket) 
    {

      try {

        String filePath="";
        for(Object obj:listOfMessages){
          System.out.println("msgs: "+obj);
          //setting path of the cert file based on ALice and bob's request
          if(obj.equals("I am Bob and I want a certificate"))
          {
            filePath="Common/bob.crt";
          }
          else if(obj.equals("I am Alice and I want a certificate"))
          {
            filePath="Common/alice.crt";
          }
        }

        // read the file into a byte array
        
        File fileToSend = new File(filePath);
        byte[] fileBytes = Files.readAllBytes(fileToSend.toPath());
        // send the file to the client
        OutputStream out = clientSocket.getOutputStream();
        out.write(fileBytes);
        out.flush();
    //close the socket and server
  out.close();
  
        
    } catch (IOException e) {
        e.printStackTrace();

    }

  
      


return null;


    }


}