
import java.lang.*;
import java.util.*;


// This class is used to run different threads on Trudy, Alice, KDC and Bob
public class Multithreading {
    
    public static void main(String[] args)
    {
    
    Alice alice = new Alice();
    Bob bob = new Bob();
    BobClient bobClient = new BobClient();

    CA ca=new CA();

    Thread a = new Thread(alice);
    Thread bc = new Thread(bobClient);

    Thread b = new Thread(bob);
    Thread c = new Thread(ca);

    c.start();
    bc.start();
    try {
        bc.join();
    } catch (InterruptedException e) {
        // TODO Auto-generated catch block
        e.printStackTrace();
    }
    a.start();
    b.start();
    
    }
}
