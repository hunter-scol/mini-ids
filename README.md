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
  - Adds to Alerts.log.
  - Filters non-threatening packets and only flags for connection attempts.
  - Reset threshold allows for possible attackers to be re-recognized.

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

  - I wanted to include flood attack detection as well becuase it uses many of the same tools in its creation.  I had to limit the number of ports included in an attack to alert a flood scan because in my research I saw that most flood scans attack a few ports with many pings and port scan attacks target many ports with few pings.  I considered making the differentiating variable the ammount of probes on one port individually, but I figured this would miss flood attacks which target more than one ports.  this being said if a flood was spread across more ports than what you have your threshold set to you will not recognize those, but I figured this would be the better trade off as the pattern seems more likely to be a flood is many probes on a few ports and a port scan attack is a few probes on many ports
## Ethical Disclaimer:
DO NOT use this tool to scan any networks that you are unauthorized to scan.