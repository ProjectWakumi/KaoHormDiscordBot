"""KaoHorm Discord Bot — จุดเริ่มทำงานของบอท"""
from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path

import discord
from discord.ext import commands
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

EXTENSIONS = [
    "cogs.SecurityGuard",
    "cogs.version_status",
]


def setup_logging() -> None:
    (BASE_DIR / "logs").mkdir(exist_ok=True)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    console = logging.StreamHandler()
    console.setFormatter(fmt)
    file = RotatingFileHandler(
        BASE_DIR / "logs" / "kaohorm.log",
        maxBytes=1_000_000,
        backupCount=3,
        encoding="utf-8",
    )
    file.setFormatter(fmt)
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.addHandler(console)
    root.addHandler(file)


log = logging.getLogger("kaohorm")


class KaoHorm(commands.Bot):
    def __init__(self) -> None:
        # ไม่ต้องใช้ Privileged Intents (ระบบลบข้อความไม่ต้องอ่านเนื้อหา)
        intents = discord.Intents.default()
        super().__init__(
            command_prefix=commands.when_mentioned,
            intents=intents,
            help_command=None,
        )

    async def setup_hook(self) -> None:
        for ext in EXTENSIONS:
            try:
                await self.load_extension(ext)
                log.info("โหลด %s สำเร็จ", ext)
            except Exception:
                log.exception("โหลด %s ไม่สำเร็จ", ext)

        dev_guild = os.getenv("DEV_GUILD_ID", "").strip()
        try:
            if dev_guild.isdigit():
                guild = discord.Object(id=int(dev_guild))
                self.tree.copy_global_to(guild=guild)
                synced = await self.tree.sync(guild=guild)
                log.info("Sync %d คำสั่งไปยังเซิร์ฟเวอร์ทดลอง %s", len(synced), dev_guild)
            else:
                synced = await self.tree.sync()
                log.info("Sync %d คำสั่งแบบ Global", len(synced))
        except discord.HTTPException:
            log.exception("Sync Slash Commands ไม่สำเร็จ")

    async def on_ready(self) -> None:
        log.info("KaoHorm ออนไลน์ในชื่อ %s (id=%s)", self.user, getattr(self.user, "id", "?"))


def main() -> None:
    setup_logging()
    token = os.getenv("DISCORD_TOKEN", "").strip()
    if not token:
        raise SystemExit("ไม่พบ DISCORD_TOKEN — คัดลอก .env.example เป็น .env แล้วใส่โทเคนก่อน")
    KaoHorm().run(token, log_handler=None)


if __name__ == "__main__":
    main()
