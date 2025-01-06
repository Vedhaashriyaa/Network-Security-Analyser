import java.time.LocalDateTime;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class DeviceStats {
    String macAddress;
    String ipAddress;
    LocalDateTime firstSeen;
    LocalDateTime lastSeen;
    long tcpPackets;
    long udpPackets;
    long httpPackets;
    long httpsPackets;
    long totalBytes;
    Set<Integer> uniquePorts;

    public DeviceStats(String macAddress, String ipAddress) {
        this.macAddress = macAddress;
        this.ipAddress = ipAddress;
        this.firstSeen = LocalDateTime.now();
        this.lastSeen = LocalDateTime.now();
        this.uniquePorts = ConcurrentHashMap.newKeySet();
    }
}
