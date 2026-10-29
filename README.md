# Mini Ids
A lightweight network intrusion detection system written in Python

## Features
- ### Selection Menu:
    - Menu for changing settings in the program.
- ### TCP Port Scan Detection:
    - flags sources doing repeated TCP scans in a predetermined window.
    - filters un-threatening packets and only flags for connection attempts.
    - sliding detection window allows you to discard normal internet traffic.
    - two-tier detection system which tracks possible attackers and elivates them to attackers based on a programable threshold.
    - cooldown system to make alerts managable.
    - reset threshold allows for posible attackers to be re-recognized.
    - persistent alert.log tracks the amount of time sources have been added to the attackers list and can be displayd as a CSV file.

## How To:

- ### running in Pycharm
    - open the project then run this in Pycharm's terminal (from project root)
  ```bash
    sudo .venv/bin/python ids.py
    ```
    - ***note** 'sudo' is required because capturing network packages needs root privilage.*

## Menu Navigation:
| Option | Default | Description |
|---|---|---|
| `--iface` | `lo` | Network interface to watch |
| `--pos-threshold` | `10` | Unique ports before a source is a possible attacker |
| `--atck-threshold` | `50` | Unique possible attacker enteries befor source is an attacker |
| `--window-knock` | `5` | Number of seconds in a port scan window |
| `--window-pos` | `60` | Number of seconds in a possible attacker retention window |
| `--window-atck` | `6` | Number of seconds in an attacker retention window |

## Design Choices:

- ### Kernal Level SYN Filter:

  - At the beggining of this project I was having a problem where I was dropping a large number of incoming packets so to fix this problem I included a filter to only recognize SYN packets which indicate an attempt at a TCP connection.  In trade off though, the only packets which this IDS detects are those which start with SYN
- ### Two Alert Tiers:

    - I decided to use two seperate alert tiers in order to recognize when a source may be trying to attack but also at the same time have a seperate list which indicates sources which have passed a larger threshold.
- ### Sliding Detection Window:

    - Using a sliding detection window it becomes possible to exclude sources which may be repeatedly pinging you for the purpose of normal network traffic.

## Ethical Disclaimer:
DO NOT use this tool to scan any networks that you are unauthorized to scan.
