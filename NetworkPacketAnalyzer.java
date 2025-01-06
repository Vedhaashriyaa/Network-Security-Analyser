import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.util.NifSelector;
import java.time.*;
import java.util.concurrent.*;
import java.util.logging.*;

public class NetworkPacketAnalyzer {
    private static final Logger LOGGER = Logger.getLogger(NetworkPacketAnalyzer.class.getName());
    private final ExecutorService executorService;
    private final ConcurrentHashMap<String, DeviceStats> deviceStats = new ConcurrentHashMap<>();
    private final PcapHandle handle;
    private volatile boolean isRunning = true;

    public NetworkPacketAnalyzer() throws PcapNativeException, NotOpenException {
        this.executorService = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());
        
        // Select network interface for capturing
        PcapNetworkInterface nif = new NifSelector().selectNetworkInterface();
        if (nif == null) {
            throw new IllegalStateException("No network interface selected");
        }

        // Open the selected interface for capture
        this.handle = nif.openLive(
            65536,                          // snaplen (maximum number of bytes to capture per packet)
            PcapNetworkInterface.PromiscuousMode.PROMISCUOUS,
            1000                            // read timeout in milliseconds
        );

        // Set filter to capture specific types of traffic (customize as needed)
        handle.setFilter(
            "tcp or udp", 
            BpfProgram.BpfCompileMode.OPTIMIZE
        );
    }

    public void startCapture() {
        executorService.submit(this::processPackets);
        executorService.submit(this::analyzeTrafficPatterns);
        executorService.submit(this::detectAnomalies);
    }

    private void processPackets() {
        while (isRunning) {
            try {
                Packet packet = handle.getNextPacket();
                if (packet != null) {
                    analyzePacket(packet);
                }
            } catch (NotOpenException e) {
                LOGGER.log(Level.SEVERE, "Error capturing packet", e);
                break;
            }
        }
    }

    private void analyzePacket(Packet packet) {
        try {
            PacketAnalyzer.analyzePacket(packet, deviceStats);
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Error analyzing packet", e);
        }
    }

    public void shutdown() {
        isRunning = false;
        executorService.shutdown();
        handle.close();
    }
}
