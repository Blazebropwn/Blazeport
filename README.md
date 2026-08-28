# BlazePort

A lightweight Python TCP port scanner for **authorized security testing and learning**.

## Features

- Concurrent TCP connect scanning with a bounded worker pool
- Hostname resolution and basic service identification
- Optional banner grabbing
- Configurable timeout, range, and worker count
- TXT and CSV result exports
- Defensive validation of CLI parameters

## Usage

Python 3.9+ is required; there are no third-party dependencies.

```bash
git clone https://github.com/Blazebropwn/Blazeport.git
cd Blazeport
python blazeport.py --target 127.0.0.1 --start-port 1 --end-port 1024
```

Optional banner grabbing and concurrency tuning:

```bash
python blazeport.py --target 127.0.0.1 --start-port 20 --end-port 443 --banner
python blazeport.py --target 127.0.0.1 --workers 50 --timeout 0.8
```

## Responsible use

Use BlazePort only on systems you own or have explicit permission to test. Unauthorized port scanning may violate policies or laws and can trigger monitoring systems.

## License

MIT
