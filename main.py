"""
PyShark - working with Wireshark
Scapy - Packet manipulation
NetworkX - Creation, Building, Manipulation
            complex networks
Matplotlib & Seaborn - data visualization
Pandas - data analysis and manipulation
PySimpleGui - GUI
dpkt - Creation and parsing of packets
pygeoip


Potential tracks:-
- Network Anomaly Detection
- Network Visualization
- Packet Capture and Analysis
"""
import dpkt
import socket
import pygeoip


gi = pygeoip.GeoIP('GeoLiteCity.dat') # GeoIP database object

def retKML(dstip, srcip):
    dst = gi.record_by_name(dstip) #returns a dictionary record
    src = gi.record_by_name('197.221.254.157') # your own ip over here
    # '197.221.254.157'

    try:
        dstLongitude = dst['longitude']
        dstLatitude = dst['latitude']
        srcLongitude = src['longitude']
        srcLatitude = src['latitude']
        kml = (
            '<Placemark>\n'
            '<name>%s</name>\n'
            '<extrude>1</extrude>\n'
            '<tessellate>1</tessellate>\n'
            '<styleUrl>#transBluePoly</styleUrl>\n'
            '<LineString>\n'
            '<coordinates>%.6f,%.6f,0\n%.6f,%.6f,0</coordinates>\n'
            '</LineString>\n'
            '</Placemark>\n'
            '\n'
              )%(dstip, dstLongitude, dstLatitude , 31.0345728, -17.7373184)

        # long - 31.0345728
        # lat - -17.7373184
        return kml
    except:
        return ''



def plotIPs(pcap):
    kmlPts = ''
    for(ts, buf) in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            src = socket.inet_ntoa(ip.src) # only accommodates the IPv4
            dst = socket.inet_ntoa(ip.dst)
            KML = retKML(dst, src)
            kmlPts = kmlPts + KML
        except:
            pass
    return kmlPts


def main():
    f = open('wire.pcap','rb')  # opens the file that contains the specified packets from Wireshark and reads as binaries
    # hence we have the mode set to 'rb' - read file and binary stream
    pcap = dpkt.pcap.Reader(f)  # reads the open file from binary mode -> pcap

    kmlheader = '<?xml version="1.0" encoding="UTF-8"?>\n<kml xmlns="http://www.opengis.net/kml/2.2">\n<Document>\n'\
    '<name>Packet Visualization</name>\n'\
    '<Style id="transBluePoly">'\
    '<LineStyle>'\
    '<width>1.5</width>'\
    '<color>880808</color>'\
    '</LineStyle>'\
    '</Style>'
    # 880808 501400E6
    kmlfooter = '</Document>\n</kml>\n'
    kmlTarget = open("output_data.kml", "w")
    kmlTarget.write( kmlheader + plotIPs(pcap) + kmlfooter)

#    print( kmlheader + plotIPs(pcap) + kmlfooter)


if __name__ == '__main__':
    main()


    """
    KML - Keyhole Markup Language 
    file format used to display geographic data in Earth browsers
    XML-based format that defines geographic features such as
    + points 
    + lines
    + polygons
    + 3d models
    along with their associated attributes and styles
    
    Key features:
    - Geographic data:= KML can represent geographic features (routes,areas)
    - Visualizations:= customize the appearance of geographic data 
    - Interactivity:= addition of functionality on KML such as pop-ups
    - Sharing and Collaboration:= easily shared and viewed by others
    
    Common use Cases:
    Software: Google Earth
    Mapping and Geo-visualization, GIS Applications, Navigation etc 
    
    <?xml version="1.0" encoding="UTF-8"?>
    <kml xmlns="http://www.opengis.net/kml/2.2">
        <Document>
            <name>Simple Point</name>
                <Placemark> <!-- defines any geographic feature (route, area, etc...) --->
                    <name>Home Sweet Home</name>
                        <Point>
                            <coordinates>-122.082200,37.422220</coordinates> <!-- specifies the longitude & latitude of the point--->
                        </Point>
                </Placemark>
        </Document>
    </kml>
    
    When opened in a KML viewer such as Google Earth, it will display a
    marker at the specified coordinates with the label "Home Sweet Home"
    """


    """
    pcap
    PCAP - Packet Capture. Its a technology and file format used to capture
    and save network traffic data. This data then be analyzed to 
    troubleshoot network issues, 
    monitor network performance, 
    or identify potential security threats.
    
    Key points about PCAP:
    - File format: PCAP files store captured network packets in a standardized
    format.
    - Packet Data Data: Each packet in a PCAP file contains information like:
        + Timestamp
        + Source and destination addresses
        + Protocol type 
        + Payload data
    
    - Analysis Tools: Many tools can analyze PCAP files, including:
    Wireshark:
    tcpdump
    Network security tools for threat detection and incident response.
    
    """

    """
    Dunder variables are special variables 
    used to provide access to internal object attributes.
    """

    """
    Socket Module in Python provides a low-level interface for
    network communication.
    It allows you to create a network sockets, which are endpoints
    for communication between two programs running on different machines
    
    Key functionalities:
    Creating sockets: You can create different types of sockets, such
    as TCP or UDP sockets, using the socket() function.
    
    Binding sockets: This involves associating a socket with a specific
    IP address and port number.

    Listening for connections: A server socket can listen for incoming 
    connections  
    
    Accepting connections: The server can accept incoming connections and
    create new socket objects for each client.
    
    Connecting to servers: A client socket can connect to a server
    socket.
    
    Sending and receiving data: Once a connection is established, data
    can be sent and received using the send() and recv() methods.
    
    Closing sockets: After communication is finished, sockets can be closed
    using the close() method.
    
    Common use cases:
    - Client-server applications: Building network applications where a
    server provides services to multiple clients.
    - Peer-to-peer communication: Creating applications where nodes can 
    directly communicate with each other.
    - Custom network protocols: Implementing custom protocols for specific
    communication needs.
    
    """

    """
    Understanding the Python for loop with pcap
    The for loop is being used for packet capture and analysis
    
    Breakdown:
    iterates over each packet within the input_stream.data file
    
    2. Unpacking tuple assignments:
    - in each iteration, the loop unpacks a tuple into two variables"
    that is ts and buf
    ts: likely the timestamp associated with the packet. It indicates when the
        packet was captured.
    buf: likely the raw packet data often in byte format.
    
    Example:
    
    f = open('wire.pcap','r+b')
    pcap = dpkt.pcap.Reader(f)
    kml = ''
    
    # plot the ips onto the kml file
    
    for (ts, raw) in pcap:
        # process packet by packet
        print(f"Timestamp: {ts}")
        # extract information from the packet buffer (e.g., using Scapy)
        packet = scapy.Ether(buf)
        print(f"Source MAC: {packet.src}" )
        print(f"Destination MAC: {packet.dst}")
    """

    """
    ip = eth.data # extract the payload
     src = socket.inet_ntoa(ip.src)
     converts the source IP address from IP to a human-readable string format.
     the function from the socket module takes a packed binary representation
     of an IPv4 address and converts it into a dotted-quad string format
     e.g., ("192.168.1.1")
     
     inet_ntoa():-
     a python function from the socket module that converts an IPv4 address
     from its binary representation a (32-bit integer) to a human readable
     dotted-quad string format (e.g., "192.168.1.1").
     
     So the function inet_ntoa() is derived from the following:
     inet: internet protocol
     n: network
     to: to 
     a: ascii
     Literally means "convert an IP address from network format to ASCII format"
    """

    """
    Scapy
    
    A versatile Python-based library that empowers you to craft, send,
    sniff, dissect, and manipulate network packets. It provides a user-
    friendly interface to interact various network protocols, making it
    an invaluable tool for network engineers, security researchers, and 
    developers.
    
    Key features:
    Packet Crafting:
        - Create custom packets with specific protocols, headers, and payloads
        - Modify existing packets to simulate attacks or test network behavior.
    
    Packet Sending: 
        - Transmit crafted packets to target hosts or networks.
        - Perform various network scans and probes.
        
    Pack Sniffing:
        - Capture packets from the network interface.
        - Filter packets based various criteria (e.g., IP address, port
          number, protocol)
        - Analyze captured packets in detail.
        
    Protocol Dissection:
        - Parse packets into their constituent layers (e.g., Ethernet, IP
          TCP, UDP)
        - Extract information from each layer, such as source and destination
          addresses, port numbers, and payload data.
    
    Interactive Shell:
        - Explore network protocols and experiment with packet manipulation
          in an interactive environment.
        - Use Scapy's built-in function and commmands to perform various
          tasks.
          
    Overview:
        from scapy.all import *
        
        # create an ICMP echo request packet
        ip = IP(dst="192.168.1.1")
        icmp = ICMP()
        packet = ip/icmp
        
        
        # Send the packet
        send(packet, verbose=True)
    
    Overview(Developed):
    Scapy can be used for a wide range of network tasks, including:
    - Network Scanning: Discover hosts on a network, identify open ports,
                        and gather information about services running on
                        those hosts.
    - Protocol Analysis: Examine the structure of network protocols and 
                         troubleshoot network issues.
    - Security Testing: Simulate attacks, test network tasks, such as 
                        configuration changes or data collection.
    - Network Automation: Automate repetitive network tasks, such as
                          configuration changes or data collection.
    
    
    ICMP
    Internet Control Message Protocol
    ICMP is a network protocol for error reporting and control messages.
    It's often used to diagnose network problems and provide feedback
    about the status of network connections. 
    
    Key ICMP Message Types:
        - Echo Request:
            This is the most common ICMP message, often used for pinging a
            host. It's often used to diagnose network problems and provide
            feedback about the status of network connections.
        - Echo Reply:
            This is the response to an echo request. It confirms that the 
            destination host is reachable and provides information about the 
            round-trip time.
        - Destination Unreachable
           This message is sent when a packet cannot be delivered to its 
           destination due to various reasons, such as network congestion,
           host unreachable, or protocol unreachable. 
        - Time Exceeded:
            This message is sent when a packet's time-to-live (TTL) expires
            before it reaches its destination.
        - Parameter Problem:
            This message is sent when a packet contains invalid parameters
            or options.
            
        ICMP in Practice:
        Pinging a Host: When you ping a host, you're sending an ICMP echo
        request. The host responds with an ICMP echo reply.
        
        Network Troubleshooting: Network administrators use ICMP to diagnose
        network connectivity issues. By analyzing ICMP error messages, they 
        can identify problems and troubleshoot network failure.  
        
        Security Tools: ICMP can be used in security tools to detect network
        intrusions and anomalies. For example, ICMP flood attacks can overwhelm
        network devices.
        
        In essence, ICMP is a vital protocol for network communication and 
        troubleshooting. It helps ensure the reliability and efficiency of 
        network services.
        
    """


