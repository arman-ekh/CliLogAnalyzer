# Advanced HTTP Log Analyzer & CLI Tool

A lightweight, high-performance, and memory-efficient Command Line Interface (CLI) application developed in **Pure Java SE** for parsing, analyzing, and monitoring HTTP server log files.

---

# Getting Started

You can compile and run this project using the standard Java Development Kit (JDK) command-line tools.

## Prerequisites

* Java Development Kit (JDK) 17 or later
* A terminal (Command Prompt, PowerShell, Bash, or Zsh)

---

## 1. Compile the Source Code

Open a terminal in the project root directory (the directory containing the `src/` folder).

### Windows

```bash
mkdir bin
javac -d bin src/Main.java src/enums/*.java
```

### Linux

```bash
mkdir -p bin
javac -d bin src/Main.java src/enums/*.java
```

### macOS

```bash
mkdir -p bin
javac -d bin src/Main.java src/enums/*.java
```

---

## 2. Run the Application

After successful compilation, navigate to the `bin` directory and execute the application.

```bash
cd bin
java Main <path-to-log-file>
```

### Example

Windows:

```bash
java Main C:\logs\access.log
```

Linux / macOS:

```bash
java Main /var/log/apache2/access.log
```

---

## Command-Line Arguments

The application supports the following optional command-line arguments to customize log analysis.

| Argument         | Description                                                                                                                |
| ---------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `--top <number>` | Displays the top **N** most frequently requested endpoints. For example, `--top 10` shows the 10 most requested endpoints. |
| `--start <hour>` | Starts log analysis from the specified hour (24-hour format). Entries before this hour are ignored.                        |
| `--end <hour>`   | Ends log analysis at the specified hour (24-hour format). Entries after this hour are ignored.                             |

### Examples

Analyze the entire log file:

```bash
java Main access.log
```

Show the top 10 most requested endpoints:

```bash
java Main access.log --top 10
```

Analyze only requests between **09:00** and **17:00**:

```bash
java Main access.log --start 9 --end 17
```

Combine multiple options:

```bash
java Main access.log --top 5 --start 8 --end 12
```

> **Note**
>
> * `--top` expects a positive integer.
> * `--start` and `--end` use the 24-hour clock (`0`–`23`).
> * If `--start` and `--end` are omitted, the entire log file is analyzed.
> * The arguments can be combined in any order.

---
### Challenge: False Positives in Spike Detection (Low Traffic Bias)
* **The Problem:** In early versions, if only 1 request occurred at 4:00 AM and failed with a `5xx` error, the hourly error rate calculated to 100%. This triggered a critical alert, even though a single isolated error during low-traffic hours is not a real system crisis.
* **The Solution:** Added a minimum threshold check (`MIN_ERROR_THRESHOLD = 5`). The algorithm now only flags an hour as a critical spike if the raw count of errors is meaningful (e.g., more than 5 errors) AND it exceeds the day's average error rate.
### Challenge: Processing Compressed `.gz` Logs Without Disk I/O
* **The Problem:** Production servers store rotated logs in Gzip (`.gz`) format. Extracting a multi-gigabyte file onto the server's disk before parsing wastes significant storage space and introduces slow Disk I/O operations.
* **The Solution:** After researching the most efficient way to handle Gzip streams in Java, I chose to avoid manual extraction. Instead, I integrated Java's native `GZIPInputStream` to wrap the file stream. This allows the tool to decompress and parse the log data **on the fly (in-memory)** line-by-line, resulting in zero disk usage and maximum throughput.
---
### Optimized Data Structures for Frequency Counting
* **HashSet (for Unique IPs):** Used to track unique client IP addresses. Since a `HashSet` naturally rejects duplicate entries and backed by a hash table, it allows us to check and insert new IPs with an optimal **$O(1)$** time complexity, keeping the process fast even with millions of logs.
* **HashMap (for Top Endpoints):** Utilized to store "Key-Value" pairs (Endpoint Path -> Hit Count). It provides **$O(1)$** lookups and updates for counting request frequencies, which is then efficiently sorted using Java Streams to extract the top $N$ paths.

---
## Features

* High-performance log parsing
* Memory-efficient processing for large log files
* Pure Java SE implementation
* Zero external dependencies
* Cross-platform (Windows, Linux, and macOS)





