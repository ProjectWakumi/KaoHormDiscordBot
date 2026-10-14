"""แสดงเวอร์ชันจาก GitHub (version.json) เป็นสถานะบอท: Watching KaoHorm | Version X"""
from __future__ import annotations

import logging
import os

import aiohttp
import discord
from discord.ext import commands, tasks

log = logging.getLogger("kaohorm.version")

VERSION_URL = os.getenv(
    "VERSION_URL",
    "https://raw.githubusercontent.com/ProjectWakumi/KaoHormDiscordBot/main/version.json",
)


class VersionStatus(commands.Cog):
    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot
        self.current_version: str | None = None
        self.session: aiohttp.ClientSession | None = None

    async def cog_load(self) -> None:
        self.session = aiohttp.ClientSession()
        self.check_version.start()

    async def cog_unload(self) -> None:
        self.check_version.cancel()
        if self.session:
            await self.session.close()

    async def get_github_version(self) -> str | None:
        """ดึงเวอร์ชันล่าสุดจาก GitHub — คืน None ถ้าดึงไม่ได้"""
        assert self.session is not None
        try:
            async with self.session.get(VERSION_URL, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status != 200:
                    log.warning("ดึง version.json ไม่สำเร็จ: HTTP %s", resp.status)
                    return None
                data = await resp.json(content_type=None)  # raw.githubusercontent ส่ง text/plain
        except (aiohttp.ClientError, TimeoutError, ValueError):
            log.warning("เชื่อมต่อ GitHub เพื่อตรวจเวอร์ชันไม่ได้", exc_info=True)
            return None
        version = str(data.get("version", "")).strip() if isinstance(data, dict) else ""
        return version or None

    async def set_status(self, text: str) -> None:
        await self.bot.change_presence(
            activity=discord.Activity(type=discord.ActivityType.watching, name=text)
        )

    @tasks.loop(minutes=5)
    async def check_version(self) -> None:
        version = await self.get_github_version()
        if version is None:
            if self.current_version is None:
                await self.set_status("KaoHorm")  # สำรองไว้ก่อน ยังไม่รู้เวอร์ชัน
            return
        if version != self.current_version:
            await self.set_status(f"KaoHorm | Version {version}")
            log.info("อัปเดตสถานะบอทเป็นเวอร์ชัน %s", version)
            self.current_version = version

    @check_version.before_loop
    async def _before_check(self) -> None:
        await self.bot.wait_until_ready()


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(VersionStatus(bot))
