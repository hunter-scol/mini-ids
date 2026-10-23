import socket, os, errno, time

target = "127.0.0.1"

for port in range(1,101):
    caller = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    resultCode = caller.connect_ex((target, port))
    if resultCode == errno.ECONNREFUSED:
        result = "Closed"
    elif resultCode == 0:
        result = "Open"
    else:
        print("resultCode not as expected")
        result = os.strerror(resultCode)

    caller.close()

    print("Scanning port", port, "result:", result)


