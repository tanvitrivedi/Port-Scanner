from scapy.all import * # The One and Only Scapy <--- For Exploit 3
from os import system,name
def clear():
    _ = system('cls')

######## Exploit 1 ########
def pingsweep():
    import subprocess 
    print("*********PING SWEEP**********")
    for ping in range(1): 
        address = "192.168.43.35"  
        res = subprocess.call(['ping', '-n', '3', address]) 
        if res == 0:
            print( "ping to", address, "OK") 
        elif res == 2: 
            print("no response from", address) 
        else: 
            print("ping to", address, "failed!")

######## Exploit 2 #######
def socket():
    print("*********PORT SCANNING USING SOCKET**********")
    import socket
    import subprocess
    import sys
    from datetime import datetime

    # Ask for input
    remoteServer    = input("Enter a remote host to scan: ")
    remoteServerIP  = socket.gethostbyname(remoteServer)

    # Print a nice banner with information on which host we are about to scan
    print( "-" * 60)
    print ("Please wait, scanning remote host", remoteServerIP)
    print ("-" * 60)

    # Check what time the scan started
    t1 = datetime.now()

    # Using the range function to specify ports (here it will scans all ports between 1 and 1024)

    # We also put in some error handling for catching errors

    try:
        for port in range(1,100):  
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((remoteServerIP, port))
            if result == 0:
                print ("Port {}: 	 Open".format(port))
            sock.close()

    except KeyboardInterrupt:
        print ("You pressed Ctrl+C")
        sys.exit()

    except socket.gaierror:
        print ('Hostname could not be resolved. Exiting')
        sys.exit()

    except socket.error:
        print ("Couldn't connect to server")
        sys.exit()

    # Checking the time again
    t2 = datetime.now()

    # Calculates the difference of time, to see how long it took to run the script
    total =  t2 - t1

    # Printing the information to screen
    print ('Scanning Completed in: ', total)

######## Exploit 3 ########

def TcpHalf():
    print("*********PORT SCANNING USING TCP-HALF SCAN**********")
    from logging import getLogger, ERROR # Import Logging Things
    getLogger("scapy.runtime").setLevel(ERROR) # Get Rid if IPv6 Warning
    import sys 
    from datetime import datetime # Other stuff
    from time import strftime
     
    try:
        target = input("[*] Enter Target IP Address: ") # Get Target Address
        min_port = input("[*] Enter Minumum Port Number: ") # Get Min. Port Num.
        max_port = input("[*] Enter Maximum Port Number: ") # Get Max. Port Num.
        try:
            if int(min_port) >= 0 and int(max_port) >= 0 and int(max_port) >= int(min_port): # Test for valid range of ports
                pass
            else: # If range didn't raise error, but didn't meet criteria
                print ("\n[!] Invalid Range of Ports")
                print ("[!] Exiting...")
                sys.exit(1)
        except Exception: # If input range raises an error
            print ("\n[!] Invalid Range of Ports")
            print ("[!] Exiting...")
            sys.exit(1)     
    except KeyboardInterrupt: # In case the user wants to quit
        print( "\n[*] User Requested Shutdown...")
        print ("[*] Exiting...")
        sys.exit(1)
     
    ports = range(int(min_port), int(max_port)+1) # Build range from given port numbers
    start_clock = datetime.now() # Start clock for scan time
    SYNACK = 0x12 # Set flag values for later reference
    RSTACK = 0x14
     
    def checkhost(ip): # Function to check if target is up
        conf.verb = 0 # Hide output
        try:
            ping = sr1(IP(dst = ip)/ICMP()) # Ping the target
            print( "\n[*] Target is Up, Beginning Scan...")
        except Exception: # If ping fails
            print( "\n[!] Couldn't Resolve Target")
            print ("[!] Exiting...")
            sys.exit(1)
     
    def scanport(port): # Function to scan a given port
        try:
            srcport = RandShort() # Generate Port Number
            conf.verb = 0 # Hide output
            SYNACKpkt = sr1(IP(dst = target)/TCP(sport = srcport, dport = port, flags = "S")) # Send SYN and recieve RST-ACK or SYN-ACK----->Three way handshake
            pktflags = SYNACKpkt.getlayer(TCP).flags # Extract flags of recived packet
            if pktflags == SYNACK: # Cross reference Flags
                return True # If open, return true
            else:
                return False # If closed, return false
            RSTpkt = IP(dst = target)/TCP(sport = srcport, dport = port, flags = "R") # Construct RST packet
            send(RSTpkt) # Send RST packet
        except KeyboardInterrupt: # In case the user needs to quit
            RSTpkt = IP(dst = target)/TCP(sport = srcport, dport = port, flags = "R") # Built RST packet
            send(RSTpkt) # Send RST packet to whatever port is currently being scanned
            print( "\n[*] User Requested Shutdown...")
            print ("[*] Exiting...")
            sys.exit(1)
     
    checkhost(target) # Run checkhost() function from earlier
    print ("[*] Scanning Started at " + strftime("%H:%M:%S") + "!\n") # Confirm scan start)
     
    for port in ports: # Iterate through range of ports
        status = scanport(port) # Feed each port into scanning function
        if status == True: # Test result 
            print ("Port " + str(port) + ": Open" )# Print status
     
    stop_clock = datetime.now() # Stop clock for scan time
    total_time = stop_clock - start_clock # Calculate scan time
    print ("\n[*] Scanning Finished!") # Confirm scan stop
    print ("[*] Total Scan Duration: " + str(total_time)) # Print scan time

######## Exploit 4 #########
def threaded():
    print("*********PORT SCANNING USING THREADING IN TCP PROTOCOL**********")
    #threading using TCP protocol
    import socket
    import time
    import threading

    from queue import Queue
    socket.setdefaulttimeout(0.25)
    print_lock = threading.Lock()

    target = input('Enter the host to be scanned: ')
    t_IP = socket.gethostbyname(target)
    print ('Starting scan on host: ', t_IP)

    def portscan(port):
       s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
       try:
          con = s.connect((t_IP, port))
          with print_lock:
             print(port, 'is open')
          con.close()
       except:
          pass

    def threader():
       while True:
          worker = q.get()
          portscan(worker)
          q.task_done()
          
    q = Queue()
    startTime = time.time()
       
    for x in range(100):
       t = threading.Thread(target = threader)
       t.daemon = True
       t.start()
       
    for worker in range(1, 500):
       q.put(worker)
       
    q.join()
    print('Time taken:', time.time() - startTime)

######## Exploit 5 ########
def UdpScan():
    print("*********PORT SCANNING USING UDP PROTOCOL**********")
    import random
    import socket
    import struct


    class SendDNSPkt:
        def __init__(self,url,serverIP,port=53):
            self.url=url
            self.serverIP = serverIP
            self.port=port
            
        def sendPkt(self):
            pkt=self._build_packet()
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1)
            sock.sendto(bytes(pkt), (self.serverIP, self.port))
            data, addr = sock.recvfrom(1024)
            sock.close()
            return data

        def _build_packet(self):
            randint = random.randint(0, 65535)
            packet = struct.pack(">H", randint)  # Query Ids (Just 1 for now)
            packet += struct.pack(">H", 0x0100)  # Flags
            packet += struct.pack(">H", 1)  # Questions
            packet += struct.pack(">H", 0)  # Answers
            packet += struct.pack(">H", 0)  # Authorities
            packet += struct.pack(">H", 0)  # Additional
            split_url = self.url.split(".")
            for part in split_url:
                packet += struct.pack("B", len(part))
                for s in part:
                    packet += struct.pack('c',s.encode())
            packet += struct.pack("B", 0)  # End of String
            packet += struct.pack(">H", 1)  # Query Type
            packet += struct.pack(">H", 1)  # Query Class
            return packet

    def checkDNSPortOpen():
        # replace 8.8.8.8 with your server IP!
        s = SendDNSPkt('www.google.com', '8.8.8.8')
        portOpen = False
        for _ in range(5): # udp is unreliable.Packet loss may occur
            try:
                s.sendPkt()
                portOpen = True
                break
            except socket.timeout:
                pass
        if portOpen:
            print('-----port is open-----!')
        else:
            print('port closed!')

    if __name__ == '__main__':
        checkDNSPortOpen()


while True:
    
    print("1) Pingsweep scan")
    print("2) Socket scan")
    print("3) Tcp Scan")
    print("4) Threaded scan")
    print("5) UDP Scan")
    print("6) Exit")
    choice = int(input("Enter a choice from 1 to 6 : "))
    clear()
    if choice==1:
        pingsweep()
    if choice==2:
        pingsweep()
        socket()
    if choice==3:
        pingsweep()
        TcpHalf()
    if choice==4:
        pingsweep()
        threaded()
    if choice==5:
        pingsweep()
        UdpScan()
    if choice==6:
        break
