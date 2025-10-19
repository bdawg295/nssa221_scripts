#!/usr/bin/env python3
"""
NSSA221 - System Administration I
Scripting Assignment 03 – Symbolic Links

Author: Brandon Wolfe
Date: 2025-10-18
"""

import os
from pathlib import Path

# --- Utility functions ---

def clear():
    os.system("clear")

def pause():
    input("\nPress Enter to continue...")

def home():
    return Path.home()

def desktop():
    d = home() / "Desktop"
    d.mkdir(exist_ok=True)
    return d

# --- Core tasks ---

def create_link():
    clear()
    print("-- Create a symbolic link --\n")
    path_str = input("Enter the path OR filename of the file to link: ").strip()
    if path_str.lower() == "quit":
        return
    file_path = Path(path_str).expanduser()

    # Search if only a filename given
    if not file_path.exists():
        matches = list(home().rglob(file_path.name))
        if not matches:
            print("Error: File not found.")
            pause()
            return
        if len(matches) > 1:
            print(f"\nMultiple files named '{file_path.name}' found:")
            for i, m in enumerate(matches, 1):
                print(f"[{i}] {m}")
            while True:
                choice = input(f"Select file (1-{len(matches)}): ").strip()
                if choice.isdigit() and 1 <= int(choice) <= len(matches):
                    file_path = matches[int(choice) - 1]
                    break
                print("Invalid selection.")
        else:
            file_path = matches[0]

    if not file_path.exists():
        print("Error: The file does not exist.")
        pause()
        return

    link_name = input(f"Enter link name [default: {file_path.name}]: ").strip() or file_path.name
    link_path = desktop() / link_name

    if link_path.exists() or link_path.is_symlink():
        confirm = input("A link or file with that name exists. Overwrite? (y/N): ").lower()
        if confirm != "y":
            return
        try:
            link_path.unlink()
        except Exception as e:
            print(f"Error removing existing file: {e}")
            pause()
            return

    try:
        os.symlink(file_path, link_path)
        print(f"Created symbolic link: {link_path} -> {file_path}")
    except Exception as e:
        print(f"Error: {e}")

    pause()

def delete_link():
    clear()
    print("-- Delete a symbolic link --\n")
    links = [f for f in desktop().iterdir() if f.is_symlink()]
    if not links:
        print("No symbolic links found on Desktop.")
        pause()
        return

    for i, link in enumerate(links, 1):
        print(f"[{i}] {link.name}")
    choice = input(f"Select a link to delete (1-{len(links)}): ").strip()
    if not choice.isdigit() or not (1 <= int(choice) <= len(links)):
        print("Invalid selection.")
        pause()
        return

    link = links[int(choice) - 1]
    try:
        link.unlink()
        print(f"Deleted link: {link}")
    except Exception as e:
        print(f"Error deleting link: {e}")
    pause()

def report_links():
    clear()
    print("-- Symbolic Link Report --\n")
    links = [p for p in home().rglob("*") if p.is_symlink()]
    if not links:
        print("No symbolic links found in your home directory.")
    else:
        for link in links:
            try:
                target = os.readlink(link)
            except:
                target = "?"
            print(f"{link} -> {target}")
        print(f"\nTotal symbolic links: {len(links)}")
    pause()

# --- Main menu ---

def main():
    clear()
    print(f"Current working directory: {Path.cwd()}\n")
    while True:
        clear()
        print("""
================ Symbolic Link Manager ================
[1] Create a symbolic link
[2] Delete a symbolic link
[3] Generate a symbolic link report
[4] Quit
======================================================
""")
        choice = input("Enter option (1-4): ").strip().lower()
        if choice in ("4", "quit"):
            print("Goodbye!")
            break
        elif choice == "1":
            create_link()
        elif choice == "2":
            delete_link()
        elif choice == "3":
            report_links()
        else:
            print("Invalid option.")
            pause()

if __name__ == "__main__":
    main()
