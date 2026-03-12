import asyncio
from threading import Thread

def start_master():
    asyncio.run(master.run())

if __name__ == "__main__":
    master = ...  # Actual setup should initialize here
    thread = Thread(target=start_master)
    thread.start()