# PacketVisualizer

## Getting Started
View how your packets are routed to places around the world using Wireshark.

*Support limited to Desktop & Laptop Users on any Architecture

## Configuration
To successfully run PacketVisualizer. A list of tools are required to view your
packets:
- A google maps: account create one to be able to view where your packets are being routed
- Any python interpreter: visit https://www.python.org/ to get yours if not already
- Any IDE: to compile the code, though cmd or related terminal can run using the python interpreter
- Wireshark: visit https://www.wireshark.org/ to get your copy of the network protocol analyzer

## Usage

- Ensure both Wireshark & Python are installed.
- Open your favorite IDE and clone this repository: https://github.com/dermpton/PacketVisualizer.git
- Run Wireshark, select any interface of choice
- You should be redirected to a separate view your packets being anaylzed for the selected interface
- navigate to the following path: press stop then File > Export Specified Packets
- Enter the filename and ensure it is exported as pcap
- Modify the python script to match your source address, find it on cmd: (ipconfig) or any respective bash command on Linux.
- Modify the file paths as to where your output_data.kml is to better find it 
- Run the application and you should see a 'output.kml' file in your directory

Head over to https://www.google.com/mymaps
Perform the following:
1. Sign-in/Login to your Google Account (Create one otherwise)
2. Click the "Create A New Map Button"
3. Click "Create" once again
4. An untitled map should appear in your browser (Refresh otherwise)
5. On the top left corner is a dashboard. Find the Untitled Layer and click Import
6. Browse the repository or drag the file with the .kml extension i.e.,output_data.kml
7. Your packet distribution across the globe should appear in extruded lines from a rough estimate of your IP or your Service providers IP.
OPTIONAL
8. On the dash click the horizontal ellipses (...) above the cloud icon and navigate to view in Google Earth

## Attribution

I'd like to thank Vinsloev Academy for both the tutorial and code analysis videos. You can check them out on Youtube: https://www.youtube.com/@VinsloevAcademy or https://vinsloev.com/#/
