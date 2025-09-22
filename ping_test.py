#!/usr/bin/env python3
"""
Author: Brandon Wolfe
Date: 9/5/25
SCripting Assign01:
** I used gpt for string formatting, as well as finding out how to get 
default gateway in numeric form
"""

import subprocess

def default_gateway():
    gateway = subprocess.check_output(
            "ip -4 route show default | awk '{print $3}'",
            shell = True, text = True).strip()
    return gateway if gateway else "gateway not found"

def option1():
    gw = default_gateway()
    print(f"Default Gateway: {gw}")

def local_connectivity():
    gw = default_gateway()
    if "No gateway" in gw:
        print(f"can't test connectivity, no gateway")
        return
    print(f"pinging default gateway {gw}")
    subprocess.run(["ping", "-c", "4", gw])

def remote_connectivity():
    r_IP = "129.21.3.17"
    print(f"pinging RIT DNS ({r_IP})")
    subprocess.run(["ping", "-c", "4", r_IP])

def test_dns():
    url = "www.google.com"
    print(f"pinging {url}")
    subprocess.run(["ping", "-c", "4", url])

def main():
    while True:
        print("Connectivity Test")
        print("1: Display Default Gateway")
        print("2: Test Local Connectivity")
        print("3: Test Remote Connectivity")
        print("4: Test DNS")
        print("5: Exit")

        choice = input("Enter choice 1-5: ").strip()

        if choice == "1":
            option1()
        elif choice == "2":
            local_connectivity()
        elif choice == "3":
            remote_connectivity()
        elif choice == "4":
            test_dns()
        elif choice == "5":
            print("exiting")
            break
        else:
            print("invalid input")
    
if __name__ == "__main__":
     main()
