import socket
import threading
import csv
import argparse
from colorama import init, Fore, Style

init(autoreset=True)

scan_results = []

# Mapping ports to common services
common_ports = {
    20: "FTP Data Transfer",
    21: "FTP Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP Proxy/Alternate"
}

def scan_single_port(ip, port):
    """Attempts to connect to a given IP and port, prints result, grabs banner if possible."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        result = sock.connect_ex((ip, port))

        if result == 0:
            print(Fore.GREEN + f"[+] Port {port} is OPEN on {ip}", end=" ")

            try:
                banner = sock.recv(1024)
                if banner:
                    banner_text = banner.decode(errors='ignore').strip()
                    print(Fore.CYAN + f"| Banner: {banner_text}")
                    scan_results.append((ip, port, banner_text))
                else:
                    service = common_ports.get(port, "Unknown Service")
                    print(Fore.YELLOW + f"| No banner received. Service Guess: {service}")
                    scan_results.append((ip, port, f"No banner. Guess: {service}"))
            except Exception:
                service = common_ports.get(port, "Unknown Service")
                print(Fore.YELLOW + f"| Banner grabbing failed. Service Guess: {service}")
                scan_results.append((ip, port, f"Banner failed. Guess: {service}"))

        sock.close()

    except Exception as e:
        print(Fore.RED + f"[!] Error scanning port {port}: {e}")

def main():
    parser = argparse.ArgumentParser(description="BlazePort - Simple Python Port Scanner with Banner Grabbing and Service Detection.")
    parser.add_argument("--target", required=True, help="Target IP address or hostname.")
    parser.add_argument("--start-port", type=int, required=True, help="Starting port number.")
    parser.add_argument("--end-port", type=int, required=True, help="Ending port number.")
    args = parser.parse_args()

    target_ip = args.target
    start_port = args.start_port
    end_port = args.end_port

    print(Fore.BLUE + f"\n[*] Scanning {target_ip} from port {start_port} to {end_port} with banner grabbing and service detection...\n")

    threads = []

    for port in range(start_port, end_port + 1):
        thread = threading.Thread(target=scan_single_port, args=(target_ip, port))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    save_results()

def save_results():
    """Saves the scan results to both text and CSV files."""
    with open("scan_results.txt", "w") as txt_file:
        txt_file.write("BlazePort Scan Results:\n\n")
        for ip, port, banner in scan_results:
            txt_file.write(f"{ip}:{port} | {banner}\n")

    with open("scan_results.csv", "w", newline='') as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(["IP", "Port", "Banner/Info"])
        for ip, port, banner in scan_results:
            csv_writer.writerow([ip, port, banner])

    print(Fore.GREEN + "\n[+] Scan results saved to scan_results.txt and scan_results.csv")

if __name__ == "__main__":
    main()
