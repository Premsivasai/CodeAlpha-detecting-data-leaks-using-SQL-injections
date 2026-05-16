import asyncio
import websockets

WS_URL = "ws://localhost:8000/api/v1/ws/attacks"


async def listen():
    print(f"Connecting to {WS_URL}...")
    try:
        async with websockets.connect(WS_URL) as ws:
            print("Connected. Listening for messages (Ctrl+C to exit)...")
            try:
                async for msg in ws:
                    print("RECEIVED:", msg)
            except asyncio.CancelledError:
                pass
    except Exception as e:
        print("Listener error:", e)


if __name__ == '__main__':
    try:
        asyncio.run(listen())
    except KeyboardInterrupt:
        print("Listener stopped by user")