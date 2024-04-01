from scapy.all import sr1, IP, TCP

def syn_scan(target_ip, port_range):
    open_ports = []

    for port in port_range:
        syn_packet = IP(dst=target_ip)/TCP(dport=port, flags="S")

        response = sr1(syn_packet, timeout=1, verbose=0)

        if response is not None:
            if response.haslayer(TCP):
                if response.getlayer(TCP).flags == 0x12:
                    open_ports.append(port)
                    print(f"open port : {port}")
                elif response.getlayer(TCP).flags == 0x14:
                    print(f"closed port : {port}")
            else:
                print(f"closed port : {port}")

    return open_ports

if __name__ == "__main__":
    target_ip = "" #test ip
    port_range = range(1, 100)

    open_ports = syn_scan(target_ip, port_range)
    print("total open ports:", open_ports)