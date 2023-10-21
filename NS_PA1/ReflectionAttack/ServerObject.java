package ReflectionAttack;

// abstract class which is being extended by Server.
abstract public class ServerObject {
  abstract public Integer getPort();
  protected static String host = "localhost";
}
