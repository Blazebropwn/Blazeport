# BlazePort - Simple Python Port Scanner

BlazePort is a fast, efficient, and lightweight TCP port scanner built in Python.  
It includes banner grabbing, basic service detection, multithreading for performance, and supports CLI parameters.

---

## Features
- Multithreaded TCP port scanning
- Banner grabbing for open ports
- Automatic service detection based on common port numbers
- Command-line interface (CLI) support
- Colored output for better readability
- Export results to `.txt` and `.csv`
- Clean, modular and extensible code

---

## Usage

```bash
python blazeport.py --target <target_ip_or_hostname> --start-port <start_port> --end-port <end_port>
```

Results will be saved in `scan_results.txt` and `scan_results.csv`.

---

## Disclaimer
> This tool is intended for **educational and authorized security testing only**.  
> Unauthorized scanning of networks that you do not own or have explicit permission to test is **illegal and unethical**.

---

## License
MIT License
