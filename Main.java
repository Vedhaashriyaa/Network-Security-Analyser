import java.io.*;
import java.util.logging.*;

public class Main {
    private static final Logger LOGGER = Logger.getLogger(Main.class.getName());

    public static void main(String[] args) {
        try {
            NetworkPacketAnalyzer analyzer = new NetworkPacketAnalyzer();
            analyzer.startCapture();

            // Keep running until user interrupts
            System.out.println("Press Enter to stop capturing...");
            new BufferedReader(new InputStreamReader(System.in)).readLine();

            analyzer.shutdown();
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error in main", e);
        }
    }
}
