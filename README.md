# CFS

**CFS (Cloudflare Fast Scanner)**  
High-performance concurrent IP latency scanner written in Go.

CFS is a lightweight, goroutine-driven TCP scanner designed to evaluate latency and reachability across large IPv4 CIDR ranges. It is optimized for high concurrency, efficient resource usage, and clean CSV output.

> ⚠️ Intended for network performance testing and research purposes.

---

## ✨ Key Features

- Massive concurrency using goroutines
- TCP connect latency measurement
- Optional HTTP validation & download test
- Configurable worker pool
- CIDR-based IP generation
- Optional random IP sampling per range
- CSV result export
- Deterministic or randomized scan modes
- Minimal memory footprint (native Go binary)

---

## 📦 Requirements

- Go 1.20 or newer
- Linux / macOS / Windows
- Sufficient file descriptor limit for high concurrency

---

## 🚀 Installation

```bash
git clone https://github.com/Ptechgithub/CFS.git
cd CFS
go build -o cfs main.go
```

Optional:

```bash
chmod +x cfs
```

---

## ▶ Usage

```bash
./cfs
```

Execution flow:

1. Load configuration from `config.json`
2. Generate IP addresses from CIDR ranges
3. Dispatch concurrent workers
4. Perform TCP connect test
5. (Optional) Perform HTTP request / download test
6. Sort and export results

---

## ⚙ Configuration

Edit `config.json`:

```json
{
  "test_domain": "chatgpt.com",
  "test_path": "/",
  "timeout": 3,
  "max_workers": 100,
  "test_download": true,
  "download_size": 102400,
  "port": 443,
  "randomize": false,
  "random_ips_per_range": 10,
  "mix_ranges": false,
  "output_file": "working_ips",
  "sort_by": "latency",
  "subnets": [
    "104.16.0.0/13",
    "172.64.0.0/13"
  ]
}
```

---

## 🧩 Configuration Parameters

| Field | Description |
|-------|------------|
| `test_domain` | Host header used for HTTP validation |
| `test_path` | HTTP path to request |
| `timeout` | Connection timeout (seconds) |
| `max_workers` | Number of concurrent goroutines |
| `test_download` | Enable download size verification |
| `download_size` | Number of bytes to download if enabled |
| `port` | Target TCP port |
| `randomize` | Enable random IP sampling |
| `random_ips_per_range` | Number of IPs per CIDR when random mode is enabled |
| `mix_ranges` | Interleave IPs from multiple ranges |
| `output_file` | Output filename (CSV) |
| `sort_by` | Sort key (`latency`, etc.) |
| `subnets` | List of CIDR ranges to scan |

---

## 📂 Using External Subnet File

If `subnets.txt` exists, it overrides the `subnets` field in `config.json`.

Example `subnets.txt`:

```
104.16.0.0/13
172.64.0.0/13
```

---

## 📊 Output Format

Results are exported as CSV:

```
ip,latency_ms,status
104.16.1.1,23,open
104.16.1.2,timeout,closed
```

If sorting is enabled, the output will be ordered accordingly.

---

## ⚡ Performance Tuning

For high-volume scans:

Increase file descriptor limit:

```bash
ulimit -n 65535
```

Tune `max_workers` based on CPU cores and RAM.  
Reduce `timeout` for faster scans.  
Enable `randomize` for large CIDR ranges (e.g., /13).

Example high-speed config:

```json
{
  "timeout": 2,
  "max_workers": 400,
  "test_download": false,
  "randomize": true,
  "random_ips_per_range": 50,
  "mix_ranges": true
}
```

---

## 🏗 Project Structure

```
CFS/
 ├── main.go
 ├── config.json
 ├── subnets.txt
 ├── result.csv
 └── README.md
```

---

## 🧠 Design Notes

- Optimized for I/O-bound workloads
- Uses atomic counters for progress tracking
- Efficient CIDR expansion
- Minimal locking overhead
- Scales well on multi-core systems

---

## 📄 License

MIT License
