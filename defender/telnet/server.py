#!/usr/bin/env python3
"""
Telnet Honeypot Server
รองรับการจำลอง telnet service สำหรับ adaptive honeypot
"""

import asyncio
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any


logger = logging.getLogger(__name__)


class TelnetSession:
    """Handles individual telnet connection"""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                 log_path: Optional[Path] = None):
        self.reader = reader
        self.writer = writer
        self.log_path = log_path
        self.remote_addr = writer.get_extra_info('peername')
        self.session_id = f"{self.remote_addr[0]}:{self.remote_addr[1]}_{datetime.now().timestamp()}"
        self.commands = []
        self.authenticated = False
        self.username = None

    async def send(self, message: str):
        """Send message to client"""
        try:
            self.writer.write(message.encode('utf-8'))
            await self.writer.drain()
        except Exception as e:
            logger.error(f"Error sending to {self.remote_addr}: {e}")

    async def readline(self) -> str:
        """Read line from client"""
        try:
            data = await asyncio.wait_for(self.reader.readline(), timeout=30.0)
            return data.decode('utf-8', errors='ignore').strip()
        except asyncio.TimeoutError:
            return ""
        except Exception as e:
            logger.error(f"Error reading from {self.remote_addr}: {e}")
            return ""

    async def log_event(self, event_type: str, data: Dict[str, Any]):
        """Log session event to JSONL"""
        if not self.log_path:
            return

        event = {
            "timestamp": datetime.now().isoformat(),
            "session_id": self.session_id,
            "remote_addr": f"{self.remote_addr[0]}:{self.remote_addr[1]}",
            "event_type": event_type,
            "data": data
        }

        try:
            with open(self.log_path, 'a') as f:
                f.write(json.dumps(event) + '\n')
        except Exception as e:
            logger.error(f"Failed to log event: {e}")

    async def handle(self):
        """Handle telnet session"""
        try:
            await self.log_event("connection", {"status": "established"})
            logger.info(f"New telnet connection from {self.remote_addr}")

            # Send banner
            await self.send("Ubuntu 20.04.3 LTS\r\n")
            await self.send(f"Hostname: honeypot-{self.remote_addr[0]}\r\n\r\n")

            # Login prompt
            await self.send("login: ")
            username = await self.readline()

            if not username:
                return

            self.username = username
            await self.log_event("login_attempt", {"username": username})

            await self.send("Password: ")
            password = await self.readline()

            await self.log_event("auth_attempt", {
                "username": username,
                "password": password,
                "success": False
            })

            # Simulate authentication delay
            await asyncio.sleep(1.5)

            # Fake authentication (always fail or succeed based on config)
            # For honeypot purposes, we can pretend to succeed
            await self.send("\r\nLogin incorrect\r\n")
            await asyncio.sleep(0.5)

            # Some attackers retry - give them another chance
            await self.send("login: ")
            username2 = await self.readline()

            if username2:
                await self.log_event("login_retry", {"username": username2})
                await self.send("Password: ")
                password2 = await self.readline()
                await self.log_event("auth_attempt", {
                    "username": username2,
                    "password": password2,
                    "success": False,
                    "attempt": 2
                })
                await self.send("\r\nLogin incorrect\r\n")

        except Exception as e:
            logger.error(f"Session error for {self.remote_addr}: {e}")
        finally:
            await self.log_event("connection", {"status": "closed"})
            try:
                self.writer.close()
                await self.writer.wait_closed()
            except:
                pass
            logger.info(f"Session closed: {self.remote_addr}")


class TelnetHoneypot:
    """Main telnet honeypot server"""

    def __init__(self, host: str = "0.0.0.0", port: int = 2323,
                 log_path: Optional[Path] = None):
        self.host = host
        self.port = port
        self.log_path = log_path
        self.server = None

        if log_path:
            log_path.parent.mkdir(parents=True, exist_ok=True)

    async def handle_client(self, reader: asyncio.StreamReader,
                          writer: asyncio.StreamWriter):
        """Handle new client connection"""
        session = TelnetSession(reader, writer, self.log_path)
        await session.handle()

    async def start(self):
        """Start telnet honeypot server"""
        self.server = await asyncio.start_server(
            self.handle_client,
            self.host,
            self.port
        )

        addr = self.server.sockets[0].getsockname()
        logger.info(f"Telnet honeypot listening on {addr[0]}:{addr[1]}")
        print(f"🔌 Telnet honeypot started on {self.host}:{self.port}")

        if self.log_path:
            print(f"📝 Logging to: {self.log_path}")

        async with self.server:
            await self.server.serve_forever()

    def run(self):
        """Run server (blocking)"""
        try:
            asyncio.run(self.start())
        except KeyboardInterrupt:
            print("\n\nTelnet honeypot stopped.")


async def run_honeypot(host: str = "127.0.0.1", port: int = 2323,
                      log_path: Optional[Path] = None):
    """Helper to run honeypot"""
    honeypot = TelnetHoneypot(host, port, log_path)
    await honeypot.start()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Default: localhost only for safety
    log_path = Path("evidence/telnet-logs/telnet.jsonl")
    honeypot = TelnetHoneypot(host="127.0.0.1", port=2323, log_path=log_path)
    honeypot.run()
