import org.pcap4j.packet.*;
import java.time.*;
import java.util.concurrent.*;
import java.util.logging.*;

public class PacketAnalyzer {
    private static final Logger LOGGER = Logger.getLogger(PacketAnalyzer.class.getName());

    public static void analyzePacket(Packet packet, ConcurrentHashMap<String, DeviceStats> deviceStats) {
        IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
        if (ipV4Packet != null) {
            String srcIp = ipV4Packet.getHeader().getSrcAddr().getHostAddress();
            String dstIp = ipV4Packet.getHeader().getDstAddr().getHostAddress();

            EthernetPacket ethernetPacket = packet.get(EthernetPacket.class);
            String srcMac = ethernetPacket.getHeader().getSrcAddr().toString();

            updateDeviceStats(srcMac, srcIp, packet, deviceStats);

            TcpPacket tcpPacket = ipV4Packet.get(TcpPacket.class);
            if (tcpPacket != null) {
                analyzePortTraffic(srcMac, tcpPacket.getHeader().getSrcPort().valueAsInt(),
                        tcpPacket.getHeader().getDstPort().valueAsInt(), deviceStats);
                detectSuspiciousPortScanning(srcMac, deviceStats);
            }
        }
    }

    private static void updateDeviceStats(String macAddress, String ipAddress, Packet packet,
                                          ConcurrentHashMap<String, DeviceStats> deviceStats) {
        DeviceStats stats = deviceStats.computeIfAbsent(macAddress, mac -> new DeviceStats(mac, ipAddress));
        stats.lastSeen = LocalDateTime.now();
        stats.totalBytes += packet.length();

        if (packet.get(TcpPacket.class) != null) {
            stats.tcpPackets++;
            TcpPacket tcpPacket = packet.get(TcpPacket.class);
            int dstPort = tcpPacket.getHeader().getDstPort().valueAsInt();
            if (dstPort == 80) stats.httpPackets++;
            if (dstPort == 443) stats.httpsPackets++;
        }
        if (packet.get(UdpPacket.class) != null) {
            stats.udpPackets++;
        }
    }

    private static void analyzePortTraffic(String macAddress, int srcPort, int dstPort,
                                           ConcurrentHashMap<String, DeviceStats> deviceStats) {
        DeviceStats stats = deviceStats.get(macAddress);
        if (stats != null) {
            stats.uniquePorts.add(srcPort);
            stats.uniquePorts.add(dstPort);
        }
    }

    private static void detectSuspiciousPortScanning(String macAddress,
                                                     ConcurrentHashMap<String, DeviceStats> deviceStats) {
        DeviceStats stats = deviceStats.get(macAddress);
        if (stats != null && stats.uniquePorts.size() > 100) {
            LOGGER.warning("Possible port scanning detected for MAC: " + macAddress);
        }
    }
}
