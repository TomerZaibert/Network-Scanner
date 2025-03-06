# Network-Scanner

## Objective
In this project, I developed a network and port scanner using Python and Scapy to identify active devices and detect open ports within a local network. The objective was to gain hands-on experience with network reconnaissance, while also improving my understanding of ARP scanning, port enumeration, and network protocols.

## Write-up
Using kali linux, I created a network_scanner.py file to run the script.

I’ll be using scapy – a packet manipulation library.

### Code

![screenshot3 - the script](https://github.com/user-attachments/assets/826c83b1-3c31-465f-8cf5-baa551767e97)

### Code Breakdown
`from scapy.all import ARP, Ether, srp`

From the library im importing:

Arp – used to create ARP request packets.

Ether – used to create an Ethernet frame.

Srp – sends and receives packet at the Data Link layer (layer 2).

`def scan_network(ip_range):`
defining a function, where (ip_range) is the network range I want to scan.

`arp_request = ARP(pdst=ip_range)`

this creates an arp request packet, pdst=ip_range set the target IP range. The arp request is basically asking “who has this ip? Tell me your MAC address"

`ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
`
we are creating an ethernet frame, we set the destination MAC address to “ff:ff:ff:ff:ff:ff” – meaning send this to every device on the network. 

`packet = ether_frame / arp_request`

the “/” operator in scapy combines packets. Now “packet” contains our ethernet frame (so it reaches every device on the network) and the arp request (asking for MAC address).

`answered, unanswered = srp(packet, timeout=2, verbose=False)
`

srp() – sends the packet and waits for a response.

We set the timeout to 2 to make sure srp() waits 2 seconds before deciding a device hasn’t responded.

Verbose = false – reduces the output from the function to be only the final results, otherwise it would return how many packets were sent, how many responses received,etc..

The function returns 2 lists - answered – devices that replied (active devices) and answered – devices that did not reply (possibly offline).

`devices = []
for sent, received in answered:
devices.append({"IP": received.psrc, "MAC": received.hwsrc})`

we create an empty list called “devices” to store the results. 

We loop through the "answered” packets. 

Received.psrc = the ip address of the responding device. Received.hwsrc = the MAC address of the responding device. 

Each device is stored in a dictionary {“ip”:…,”MAC”:…} and we append it to the devices list.

`network = input("Enter network range:")
`

we prompt the user the enter a network range.

`devices_found = scan_network(network)
 print("\nActive Devices:")
 print("IP Address\t\tMAC Address")
 print("-" * 40) for device in devices_found:
 print(f"{device['IP']}\t\t{device['MAC']}")
`

we call the scan_network function and scan the network the user inputs. Then a table is printed with the IP and MAC addresses of active devices.

### Running the Script

Used the command “ip a” to check my network range to check the the devices on my network later

![screenshot2 - checking my network range for later use](https://github.com/user-attachments/assets/3eadf9a7-c6b8-43e8-8545-e000774a70e3)

Ran the network_scanner.py file, entered my IP and it worked, the devices on my network were printed.

![screenshot6 - function results](https://github.com/user-attachments/assets/d5032620-d5a5-4b2e-ae4d-4fb877973293)

I decided the function should automatically detect the subnet instead of asking the user to input it.

### Making the Network Detection Automatic

![screenshot7 - new code with auto detection](https://github.com/user-attachments/assets/adafab89-aa04-4eef-aa5e-1d2b97c8dd41)

### Code Breakdown

`import netifaces`

import the netifaces library – a library that retrieves network interface information.

`Interfaces = netifaces.interfaces()`

This gets all available network interfaces.
`
addrs = netifaces.ifaddresses(interface)
if netifaces.AF_INET in addrs:`

checks if the interface has an IPv4 address (meaning it skips the ones who don’t).

`local_ip = ip_info['addr']
subnet_mask = ip_info['netmask']`

extracts the ip and subnet mask and enters them to a variable.

`cidr_suffix = sum(bin(int(octet)).count('1') for octet in subnet_mask.split('.'))`

converts the subnet mask into CIDR notation (for example /24). This is done by counting the number of “1” bits in the binary form of each octet.

`network_range = f"{local_ip.rsplit('.', 1)[0]}.0/{cidr_suffix}"
`

uses the first 3 octets of the ip address and appends .0 and adds the cidr suffix. This gives us the full network range.

`network_range = get_local_subnet()
if network_range is None:
    print("Could not detect local network. Please check your network connection.")`

now instead of asking the user for input we get the network range automatically using the get_local_subnet() function we just made. If the detection fails it displays an error message

`print(f"Scanning network: {network_range}")
`

lets the user know what network we are scanning.

![screenshot8 - results are not good](https://github.com/user-attachments/assets/b6500309-e9d0-47bd-93b3-e797b4e719f9)

After running the new script, the function informed me that it was scanning 127.0.0.0/8, which is not what I needed, I needed it to scan 192.168.159.128/24.</br>
This means that the script is incorrectly selecting the lo (loopback) interface which is used for communication within the same machine, instead of eth0 which is used for network communication with other devices. </br>
I needed to modify the script to skip loopback IP.</br>

### Fixing the Code

![screenshot9 - code fixes](https://github.com/user-attachments/assets/8a0457c3-9bf8-46dd-97f5-92e6b770c831)

### Code Changes
`
if local_ip.startswith("127."):
    continue`

this line was added to skip the loopback interface, since loopback Ips always start with 127.xxx we will always skip it, 127.xxx are reserved for loopback IPs.

`
network = ipaddress.IPv4Network(f"{local_ip}/{subnet_mask}", strict=False)
                return str(network)`

this line was modified to calculate the correct network range.

![screenshot10 - new results](https://github.com/user-attachments/assets/c9dcf96b-42c9-46da-b669-83af681661cb)

automatically detects the network and returns the table as it should.

### Adding a Port Scanner

Decided to add a port scanner to the network scanner.

The new script will scan the network for open devices, and then check for open ports on each discovered device by trying to connect to a few chosen ports (for simplicity). 

![screenshot11 - new code with port scanning](https://github.com/user-attachments/assets/af7270f0-734e-4ca0-9a0f-77883709487d)

![screenshot12 - 2nd part of the new code](https://github.com/user-attachments/assets/8bcf93cc-5058-44d8-92d0-be8a39f3c014)

### Code Changes

`import socket
`

socket is a library in python that allows programs to communicate over networks. </br> It provides a way to create, connect and manage network sockets. Needed to add it for the scanning of the ports.

`def scan_ports(ip, ports=[22, 80, 443, 3389]):
`

the function gets 2 paramets, the IP from the scan we made mefore and a few chosen ports to check. <br>
22 – ssh, used for remote login. <br>
80 – http, used for websites. <br>
443 – https, used for secure websites. <br>
3389 – RDP, windows remote desktop protocol. <br>

`open_ports = []
`

empty list to store all the detected open ports.

`open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))  # 0 means open, else closed
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports`

for each port that we find, we create a new socket using sock.socket(). 

Socket.AF_INET means that we are using IPv4. 

socket.SOCK_STREAM  specifies that we are using a TCP connection. I used TCP because it ensures reliable communication, it requires handshaking (SYN -> SYN-ACK -> ACK) to establish a connection, if the port is open it responds to the handshake, if it is closed the handshake is rejected or ignored. 

Sock.settimeout(1) is used to ensure that if a device doesn’t respond in 1 second it is considered close to prevent the function from hanging on to unresponsive devices. 

result = sock.connect_ex((ip, port)) 

Connect_ex() – tries to create a connection using that target IP and port, returns 0 if the port is open. 

if result == 0: <br>
    open_ports.append(port) 
    
if the port is open, the port is added to the open_ports list. 

sock.close() - The sock is closed to free system resources. 

return open_ports - Returns the list of open ports. 

The printing of the results was modified to add the open ports to the table.

![screenshot13 - new code results](https://github.com/user-attachments/assets/d7e33bc7-4dcd-46f7-902e-d3b5d805aa3c)

The script returned that no ports are open, to verify it I will use nmap.

### Verifying the Script

![screenshot14 - nmap results](https://github.com/user-attachments/assets/fe93db3b-5426-4c4a-b0de-4a47d3d86346)

Nmap shows that no port is open. But it still doesn’t 100% prove the the script is working, so I will open one of the ports and then run nmap and the script again.

I opened another terminal and ran a web server on port 80.

![screenshot15 - running a webserver on port 80](https://github.com/user-attachments/assets/bebe839b-32c6-4bb2-b1af-4fc58890fee7)

Ran nmap again

![screenshot16 - running nmap again](https://github.com/user-attachments/assets/b52fc080-8583-4b04-8a6c-1e1637e1bc11)

Nmap shows that port 80 is open, now I’ll try to run the script again and see if it returns the same results.

![screenshot17 - script doesnt return the same results](https://github.com/user-attachments/assets/4c07fea6-9a59-47d3-92cf-e87b3715c6a1)

The script doesn’t return the same results. After investigation I found that some virtual machines block ARP self-detection. <br>
I decided to add the machine’s ip manually to the script just for the check and delete it later. <br>
Added the command: <br>
`devices.append({"IP": "192.168.159.128", "MAC": "00:0c:29:c0:c1:44"}) ` <br>
before I return the devices list, just for the check and I will revert the script back after confirming it works.

![screenshot18 - script works](https://github.com/user-attachments/assets/f5733180-77c7-4bf0-a45a-fe3e8b4a4fc5)

The script works, it probably was the VM blocking the ARP request as suspected.

I reverted the script back to remove the appending of my own IP to every run of the script.


## Conclusion
By developing a Python-based network scanner, I was able to explore how ARP requests can be used to map active devices within a subnet. <br>
Additionally, integrating a port scanner allowed me to identify open services, reinforcing my understanding of network security, attack surfaces, and reconnaissance techniques. <br>
During the project I faced challenges that researching and resolving them really reinforced my understanding of the subject at hand.














