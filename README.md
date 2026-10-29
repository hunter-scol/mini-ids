# Mini IDS
A lightweight network intrusion detection system written in Python

## Features
- ### Selection Menu:
  - Menu for changing settings in the program.
- ### TCP Port Scan Attack Detection:
  - Flags sources doing repeated TCP scans in a predetermined window.
  - Filters non-threatening packets and only flags for connection attempts.
  - Sliding detection window allows you to discard normal internet traffic.
  - Two-tier detection system which tracks possible attackers and elevates them to attackers based on a programmable threshold.
  - Cooldown system to make alerts manageable.
  - Reset threshold allows for possible attackers to be re-recognized.
  - Persistent alerts.log tracks the number of times sources have been added to the attackers list and can be displayed as a CSV file.
- ### TCP Port Flood Attack Detection
  - Flags sources attempting to flood a specific set of TCP ports.
  - Adds to alerts.log.
  - Filters non-threatening packets and only flags for connection attempts.
  - Cooldown prints one alert per flood instead of one per packet.

## How To:

- ### Running in PyCharm
  - Open the project, then run this in PyCharm's terminal (from the project root):
  ```bash
    sudo .venv/bin/python ids.py
    ```
  - ***Note:** 'sudo' is required because capturing network packets needs root privileges.*

## Menu Navigation:
| Option | Default | Description |
|---|---|---|
| `--iface` | `lo` | Network interface to watch |
| `--pos-threshold` | `10` | Unique ports probed within the knock window before a source is flagged as a possible attacker |
| `--atck-threshold` | `50` | Unique ports probed within the knock window before a possible attacker is escalated to attacker and logged |
| `--flood-threshold` | `200` | SYNs from one source within the flood window before it counts as a SYN flood |
| `--ports-threshold` | `5` | Max different ports a flood can hit (more than this looks like a scan, not a flood) |
| `--window-knock` | `5` | Seconds a probe stays in the port scan sliding window |
| `--window-pos` | `60` | Seconds before a possible attacker is cleared and can be alerted again |
| `--window-atck` | `60` | Cooldown in seconds between printed attacker and flood alerts for the same source |
| `--window-flood` | `1` | Seconds in the SYN flood sliding window |

## Design Choices:

- ### Kernel Level SYN Filter:

  - At the beginning of this project I was having a problem where I was dropping a large number of incoming packets, so to fix this problem, I included a filter to only recognize SYN packets which indicate an attempt at a TCP connection.  As a tradeoff, though, the only packets which this IDS detects are those which start with SYN.
- ### Two Alert Tiers:

  - I decided to use two separate alert tiers in order to recognize when a source may be trying to attack but also at the same time have a separate list which indicates sources which have passed a larger threshold.
- ### Sliding Detection Window:

  - Using a sliding detection window, it becomes possible to exclude sources which may be repeatedly pinging you for the purpose of normal network traffic.

- ### Flood detection vs Port detection

  - I wanted to include flood attack detection as well because it uses many of the same tools in its creation. I had to limit the number of ports included in an attack to alert a flood because in my research I saw that most floods attack a few ports with many SYNs, and port scan attacks target many ports with few SYNs. I considered making the differentiating variable the amount of probes on one port individually, but I figured this would miss flood attacks which target more than one port. That being said, if a flood was spread across more ports than your threshold is set to, it will not be recognized, but I figured this would be the better tradeoff, as a flood is more likely to be many probes on a few ports and a port scan attack is more likely to be a few probes on many ports.

## Testing:
All tests were run against localhost only.

- ### Port Scan (nmap)
  - **Command:** `nmap localhost`
  - **Result:**
    ```
    possible attack: source 127.0.0.1 to 127.0.0.1. 10 probes
    attack: possible attacker 127.0.0.1 elevated to attacker due to excessive probes. count: 50
    ```
  - No flood alert, as expected.

- ### SYN Flood (hping3)
  - **Command:** `sudo hping3 -S -p 80 -c 500 -i u1000 127.0.0.1`
  - **Result:**
    ```
    flood: 127.0.0.1 sent 200 SYNs in 1s
    ```
  - No port scan alerts, as expected.


## Limitations
- The program only detects SYN probes as they are the most common for establishing connection, it does this to speed up the program as to drop less packets.
- The program only detects ~75% of probes due to the fact that it is written in Python(interpreted) rather than something like C(compiled).  I chose to write this code in python because I haven't had a class in python and wanted to learn how to write code with it.
- Slow scans aren't detected.  I made a sliding window for probe retention to exclude repeated probes for the sake of normal network traffic but in the case of an attack done slowly the IDS would fail under the default conditions.
- The program can very easily be spoofed by an attacker hiding their ip address.

## Ethical Disclaimer:
DO NOT use this tool to scan any networks that you are unauthorized to scan.