import os
import time
import random
from datetime import datetime

counter = 0


def clear():
    os.system("cls" if os.name == "nt" else "clear")


def dashboard():
    global counter

    while True:
        clear()

        print("=" * 40)
        print("         SIMPLE DASHBOARD")
        print("=" * 40)

        print(f"Time: {datetime.now().strftime('%H:%M:%S')}")
        print(f"Counter: {counter}")
        print(f"CPU Usage: {random.randint(10, 90)}%")

        print("\nPress Ctrl+C to return to menu")

        counter += 1
        time.sleep(1)


def menu():
    while True:
        clear()
        print("=== MAIN MENU ===")
        print("1. View Dashboard")
        print("2. Reset Counter")
        print("3. Exit")

        choice = input("\nSelect option: ")

        if choice == "1":
            try:
                dashboard()
            except KeyboardInterrupt:
                pass

        elif choice == "2":
            global counter
            counter = 0
            print("Counter reset!")
            time.sleep(1)

        elif choice == "3":
            print("Goodbye!")
            break

        else:
            print("Invalid choice")
            time.sleep(1)


if __name__ == "__main__":
    menu()