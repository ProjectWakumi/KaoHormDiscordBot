"""🌸 KaoHorm — Sakura Security Guard

- /security setup   : สร้าง/ใช้หมวดหมู่และห้อง Security Guard ซ้ำ + ส่งประกาศ
- /security status  : ดูสถานะระบบ
- /security repair  : ซ่อมแซมห้องและประกาศ (ไม่เปลี่ยนสถานะเปิด/ปิด)
- /security toggle  : เปิด/ปิดระบบ
- /security exempt  : เพิ่ม/ลบ/ดูรายชื่อผู้ได้รับการยกเว้น

หมายเหตุด้านความปลอดภัย: การพิมพ์ในห้องนี้ไม่ได้พิสูจน์ว่าบัญชีถูกแฮ็ก
ระบบจึงลบเฉพาะข้อความตัวกระตุ้นและบันทึก Log เท่านั้น ไม่เตะ/ลบประวัติอัตโนมัติ
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import time
from pathlib import Path
from typing import Any

import discord
from discord import app_commands
from discord.ext import commands, tasks

log = logging.getLogger("kaohorm.securityguard")

CATEGORY_NAME = "🌸 SAKURA SECURITY"
CHANNEL_NAME = "🛡️・security-guard"

SAKURA_PINK = 0xFFB7C5
SAKURA_PURPLE = 0xC8A2E8

DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "security_guard.json"

REQUIRED_PERMS = {
    "view_channel": "View Channels",
    "send_messages": "Send Messages",
    "read_message_history": "Read Message History",
    "embed_links": "Embed Links",
    "attach_files": "Attach Files (สำหรับ Banner)",
    "manage_channels": "Manage Channels",
    "manage_messages": "Manage Messages",
}


def _norm(name: str) -> str:
    """ทำชื่อห้องให้เทียบกันได้ (Discord อาจตัด variation selector/ปรับตัวพิมพ์)"""
    return name.replace("\ufe0f", "").strip().lower()


class GuardStore:
    """เก็บ IDs และสถานะใน JSON — เขียนแบบ atomic + มีไฟล์สำรอง"""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.data: dict[str, dict[str, Any]] = {}
        self.load()

    def load(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        for candidate in (self.path, self.path.with_suffix(".json.bak")):
            if not candidate.exists():
                continue
            try:
                loaded = json.loads(candidate.read_text(encoding="utf-8"))
                if not isinstance(loaded, dict):
                    raise ValueError("root ต้องเป็น object")
                self.data = loaded
                if candidate is not self.path:
                    log.warning("ใช้ไฟล์สำรอง %s แทนไฟล์หลัก", candidate.name)
                return
            except (json.JSONDecodeError, ValueError, OSError):
                log.exception("อ่าน %s ไม่ได้", candidate.name)
                if candidate == self.path:
                    corrupt = self.path.with_name(f"{self.path.name}.corrupt-{int(time.time())}")
                    try:
                        shutil.copy2(self.path, corrupt)
                    except OSError:
                        pass
        self.data = {}

    def save(self) -> None:
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(self.data, ensure_ascii=False, indent=2), encoding="utf-8")
        if self.path.exists():
            try:
                shutil.copy2(self.path, self.path.with_suffix(".json.bak"))
            except OSError:
                log.warning("สำรองไฟล์ JSON ไม่สำเร็จ")
        os.replace(tmp, self.path)

    def get(self, guild_id: int) -> dict[str, Any]:
        return self.data.get(str(guild_id), {})

    def update(self, guild_id: int, **fields: Any) -> dict[str, Any]:
        rec = self.data.setdefault(str(guild_id), {})
        rec.update(fields)
        rec.setdefault("exempt_user_ids", [])
        self.save()
        return rec


class SecurityGuard(commands.Cog):
    security = app_commands.Group(
        name="security",
        description="ระบบ Sakura Security Guard",
        guild_only=True,
        default_permissions=discord.Permissions(manage_guild=True),
    )

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot
        self.store = GuardStore(DATA_FILE)
        self._locks: dict[int, asyncio.Lock] = {}

    async def cog_load(self) -> None:
        self.watchdog.start()

    async def cog_unload(self) -> None:
        self.watchdog.cancel()

    def _lock(self, guild_id: int) -> asyncio.Lock:
        return self._locks.setdefault(guild_id, asyncio.Lock())

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def missing_perms(guild: discord.Guild) -> list[str]:
        me = guild.me
        if me is None:
            return list(REQUIRED_PERMS.values())
        perms = me.guild_permissions
        if perms.administrator:
            return []
        return [label for attr, label in REQUIRED_PERMS.items() if not getattr(perms, attr)]

    @staticmethod
    def is_exempt(member: discord.abc.User, rec: dict[str, Any]) -> bool:
        if member.id in rec.get("exempt_user_ids", []):
            return True
        if isinstance(member, discord.Member):
            p = member.guild_permissions
            return p.administrator or p.manage_guild
        return False

    async def fetch_banner_file(self) -> discord.File | None:
        """ดึงรูป Banner จากข้อความที่กำหนด แล้วอัปโหลดใหม่ทุกครั้ง (URL แนบไฟล์ของ Discord หมดอายุได้)"""
        cid = os.getenv("BANNER_CHANNEL_ID", "").strip()
        mid = os.getenv("BANNER_MESSAGE_ID", "").strip()
        if not (cid.isdigit() and mid.isdigit()):
            return None
        try:
            channel = self.bot.get_channel(int(cid)) or await self.bot.fetch_channel(int(cid))
            message = await channel.fetch_message(int(mid))  # type: ignore[union-attr]
            for att in message.attachments:
                if (att.content_type or "").startswith("image/"):
                    return await att.to_file(filename="banner.png")
        except (discord.HTTPException, AttributeError):
            log.warning("ดึง Banner ไม่สำเร็จ (ตรวจสอบ BANNER_CHANNEL_ID / BANNER_MESSAGE_ID และสิทธิ์)")
        return None

    @staticmethod
    def build_embed(guild: discord.Guild, has_banner: bool) -> discord.Embed:
        embed = discord.Embed(
            title="🌸 Sakura Security Guard",
            description=(
                "ห้องนี้อยู่ภายใต้การเฝ้าระวังของ **KaoHorm**\n\n"
                "🚫 **กรุณาอย่าพิมพ์ข้อความในห้องนี้**\n"
                "ข้อความที่ถูกส่งจะถูกลบอัตโนมัติ และเหตุการณ์จะถูกบันทึกให้ผู้ดูแลตรวจสอบ\n\n"
                "💜 หากคุณเผลอพิมพ์ ไม่ต้องกังวล ผู้ดูแลจะตรวจสอบก่อนดำเนินการใด ๆ"
            ),
            color=SAKURA_PINK,
        )
        embed.add_field(name="🛡️ สถานะ", value="เปิดใช้งาน", inline=True)
        embed.set_footer(text=f"KaoHorm • {guild.name}")
        if has_banner:
            embed.set_image(url="attachment://banner.png")
        return embed

    # ------------------------------------------------------------ structure ops
    async def ensure_structure(self, guild: discord.Guild) -> tuple[discord.CategoryChannel, discord.TextChannel, list[str]]:
        rec = self.store.get(guild.id)
        created: list[str] = []

        category = guild.get_channel(rec.get("category_id", 0))
        if not isinstance(category, discord.CategoryChannel):
            category = next((c for c in guild.categories if _norm(c.name) == _norm(CATEGORY_NAME)), None)
        if category is None:
            category = await guild.create_category(CATEGORY_NAME, reason="KaoHorm Security Guard setup")
            created.append(f"หมวดหมู่ {CATEGORY_NAME}")
            log.info("สร้างหมวดหมู่ใน guild=%s", guild.id)

        channel = guild.get_channel(rec.get("channel_id", 0))
        if not isinstance(channel, discord.TextChannel):
            channel = next((c for c in category.text_channels if _norm(c.name) == _norm(CHANNEL_NAME)), None)
        if channel is None:
            channel = await guild.create_text_channel(
                CHANNEL_NAME, category=category, reason="KaoHorm Security Guard setup"
            )
            created.append(f"ห้อง {CHANNEL_NAME}")
            log.info("สร้างห้อง Security Guard ใน guild=%s", guild.id)

        # สิทธิ์: สมาชิกเห็น/ส่งข้อความได้ (เป็นห้องเฝ้าระวัง), บอทจัดการข้อความได้
        await channel.set_permissions(
            guild.default_role,
            view_channel=True,
            send_messages=True,
            read_message_history=True,
            attach_files=False,
            reason="KaoHorm Security Guard permissions",
        )
        await channel.set_permissions(
            guild.me,
            view_channel=True,
            send_messages=True,
            embed_links=True,
            attach_files=True,
            read_message_history=True,
            manage_messages=True,
            reason="KaoHorm Security Guard permissions",
        )
        self.store.update(guild.id, category_id=category.id, channel_id=channel.id)
        return category, channel, created

    async def ensure_announcement(self, guild: discord.Guild, channel: discord.TextChannel) -> tuple[discord.Message, bool]:
        """คืน (ข้อความประกาศ, สร้างใหม่หรือไม่) — ไม่สร้างซ้ำถ้าข้อความเดิมยังอยู่"""
        async with self._lock(guild.id):
            rec = self.store.get(guild.id)
            mid = rec.get("message_id")
            if mid:
                try:
                    return await channel.fetch_message(mid), False
                except discord.NotFound:
                    log.warning("ประกาศหาย (guild=%s) — กำลังสร้างใหม่", guild.id)

            banner = await self.fetch_banner_file()
            embed = self.build_embed(guild, banner is not None)
            kwargs: dict[str, Any] = {"embed": embed}
            if banner:
                kwargs["file"] = banner
            message = await channel.send(**kwargs)
            self.store.update(guild.id, message_id=message.id)
            log.info("ส่งประกาศ Security Guard (guild=%s, message=%s)", guild.id, message.id)
            return message, True

    async def _try_restore(self, guild: discord.Guild) -> None:
        rec = self.store.get(guild.id)
        if not rec.get("channel_id"):
            return
        channel = guild.get_channel(rec["channel_id"])
        if not isinstance(channel, discord.TextChannel):
            log.warning("ไม่พบห้อง Security Guard (guild=%s) — ใช้ /security repair", guild.id)
            return
        try:
            await self.ensure_announcement(guild, channel)
        except discord.Forbidden:
            log.error("กู้คืนประกาศไม่ได้: บอทไม่มีสิทธิ์ส่งข้อความ/Embed (guild=%s)", guild.id)
        except discord.HTTPException:
            log.exception("กู้คืนประกาศล้มเหลวจาก Discord API (guild=%s)", guild.id)

    # ----------------------------------------------------------------- listeners
    @commands.Cog.listener()
    async def on_message(self, message: discord.Message) -> None:
        if message.guild is None or message.author.bot:
            return
        rec = self.store.get(message.guild.id)
        if not rec or not rec.get("enabled") or message.channel.id != rec.get("channel_id"):
            return
        if self.is_exempt(message.author, rec):
            return

        # ไม่บันทึกเนื้อหาข้อความ เพื่อลดข้อมูลส่วนบุคคล
        log.warning(
            "ตรวจพบข้อความในห้อง Security Guard guild=%s channel=%s user=%s",
            message.guild.id, message.channel.id, message.author.id,
        )
        try:
            await message.delete()
            log.info("ลบข้อความตัวกระตุ้นสำเร็จ (user=%s)", message.author.id)
        except discord.Forbidden:
            log.error("ลบข้อความไม่ได้: บอทไม่มีสิทธิ์ Manage Messages (guild=%s)", message.guild.id)
        except discord.NotFound:
            pass
        except discord.HTTPException:
            log.exception("ลบข้อความล้มเหลวจาก Discord API")

    @commands.Cog.listener()
    async def on_raw_message_delete(self, payload: discord.RawMessageDeleteEvent) -> None:
        if payload.guild_id is None:
            return
        rec = self.store.get(payload.guild_id)
        if rec.get("message_id") == payload.message_id and rec.get("enabled"):
            guild = self.bot.get_guild(payload.guild_id)
            if guild:
                await asyncio.sleep(2)
                await self._try_restore(guild)

    @commands.Cog.listener()
    async def on_raw_bulk_message_delete(self, payload: discord.RawBulkMessageDeleteEvent) -> None:
        if payload.guild_id is None:
            return
        rec = self.store.get(payload.guild_id)
        if rec.get("message_id") in payload.message_ids and rec.get("enabled"):
            guild = self.bot.get_guild(payload.guild_id)
            if guild:
                await asyncio.sleep(2)
                await self._try_restore(guild)

    @tasks.loop(seconds=120)
    async def watchdog(self) -> None:
        for gid, rec in list(self.store.data.items()):
            if not rec.get("enabled"):
                continue
            guild = self.bot.get_guild(int(gid))
            if guild:
                await self._try_restore(guild)

    @watchdog.before_loop
    async def _before_watchdog(self) -> None:
        await self.bot.wait_until_ready()

    # ------------------------------------------------------------------ commands
    async def _run_setup(self, interaction: discord.Interaction, enable: bool) -> None:
        guild = interaction.guild
        assert guild is not None
        missing = self.missing_perms(guild)
        if missing:
            log.warning("Setup ไม่ผ่าน: บอทขาดสิทธิ์ %s (guild=%s)", missing, guild.id)
            await interaction.followup.send(
                "⚠️ บอทยังขาดสิทธิ์ที่จำเป็น:\n" + "\n".join(f"• {m}" for m in missing)
                + "\n\nกรุณาเพิ่มสิทธิ์ (ไม่ต้องให้ Administrator) แล้วลองใหม่", ephemeral=True,
            )
            return
        try:
            category, channel, created = await self.ensure_structure(guild)
            _, new_msg = await self.ensure_announcement(guild, channel)
        except discord.Forbidden:
            log.exception("Setup ล้มเหลว: Forbidden (guild=%s)", guild.id)
            await interaction.followup.send(
                "❌ บอทไม่มีสิทธิ์พอ — ตรวจสอบลำดับ Role ของบอทให้อยู่สูงพอและมีสิทธิ์ครบ", ephemeral=True)
            return
        except discord.HTTPException:
            log.exception("Setup ล้มเหลว: HTTPException (guild=%s)", guild.id)
            await interaction.followup.send("❌ Discord API ผิดพลาด ลองใหม่อีกครั้งภายหลัง", ephemeral=True)
            return

        if enable:
            self.store.update(guild.id, enabled=True)
        log.info("Setup สำเร็จ guild=%s created=%s new_announcement=%s", guild.id, created, new_msg)

        embed = discord.Embed(title="🌸 ตั้งค่า Security Guard สำเร็จ", color=SAKURA_PURPLE)
        embed.add_field(name="ห้อง", value=channel.mention, inline=True)
        embed.add_field(name="สถานะ", value="เปิดใช้งาน" if self.store.get(guild.id).get("enabled") else "ปิดอยู่", inline=True)
        embed.add_field(
            name="สิ่งที่ทำ",
            value=("• " + "\n• ".join(created) if created else "• ใช้หมวดหมู่/ห้องเดิม ไม่สร้างซ้ำ")
            + ("\n• ส่งประกาศใหม่" if new_msg else "\n• ประกาศเดิมยังอยู่"),
            inline=False,
        )
        await interaction.followup.send(embed=embed, ephemeral=True)

    @security.command(name="setup", description="ตั้งค่า Security Guard อัตโนมัติ")
    @app_commands.checks.has_permissions(manage_guild=True)
    async def setup_cmd(self, interaction: discord.Interaction) -> None:
        await interaction.response.defer(ephemeral=True)
        await self._run_setup(interaction, enable=True)

    @security.command(name="repair", description="ซ่อมแซมห้องและประกาศ Security Guard")
    @app_commands.checks.has_permissions(manage_guild=True)
    async def repair_cmd(self, interaction: discord.Interaction) -> None:
        await interaction.response.defer(ephemeral=True)
        await self._run_setup(interaction, enable=False)

    @security.command(name="status", description="ดูสถานะ Security Guard")
    @app_commands.checks.has_permissions(manage_guild=True)
    async def status_cmd(self, interaction: discord.Interaction) -> None:
        guild = interaction.guild
        assert guild is not None
        rec = self.store.get(guild.id)
        if not rec:
            await interaction.response.send_message("ยังไม่ได้ตั้งค่า — ใช้ `/security setup`", ephemeral=True)
            return
        channel = guild.get_channel(rec.get("channel_id", 0))
        announce = "ไม่ทราบ"
        if isinstance(channel, discord.TextChannel) and rec.get("message_id"):
            try:
                await channel.fetch_message(rec["message_id"])
                announce = "✅ มีอยู่"
            except discord.NotFound:
                announce = "❌ หาย (จะกู้คืนอัตโนมัติ หรือใช้ /security repair)"
            except discord.HTTPException:
                announce = "⚠️ ตรวจสอบไม่ได้"
        missing = self.missing_perms(guild)
        embed = discord.Embed(title="🌸 Security Guard Status", color=SAKURA_PINK)
        embed.add_field(name="เปิดใช้งาน", value="✅" if rec.get("enabled") else "⛔", inline=True)
        embed.add_field(name="ห้อง", value=channel.mention if channel else "❌ ไม่พบ", inline=True)
        embed.add_field(name="ประกาศ", value=announce, inline=True)
        embed.add_field(name="ผู้ได้รับการยกเว้น", value=str(len(rec.get("exempt_user_ids", []))), inline=True)
        embed.add_field(name="สิทธิ์บอท", value="ครบ ✅" if not missing else "ขาด: " + ", ".join(missing), inline=False)
        await interaction.response.send_message(embed=embed, ephemeral=True)

    @security.command(name="toggle", description="เปิด/ปิดระบบ Security Guard")
    @app_commands.describe(enabled="เปิดหรือปิด")
    @app_commands.checks.has_permissions(manage_guild=True)
    async def toggle_cmd(self, interaction: discord.Interaction, enabled: bool) -> None:
        guild = interaction.guild
        assert guild is not None
        if not self.store.get(guild.id):
            await interaction.response.send_message("ยังไม่ได้ตั้งค่า — ใช้ `/security setup` ก่อน", ephemeral=True)
            return
        self.store.update(guild.id, enabled=enabled)
        log.info("Security Guard enabled=%s (guild=%s, by=%s)", enabled, guild.id, interaction.user.id)
        await interaction.response.send_message("✅ เปิดใช้งานแล้ว" if enabled else "⛔ ปิดการใช้งานแล้ว", ephemeral=True)

    @security.command(name="exempt", description="จัดการรายชื่อผู้ได้รับการยกเว้น")
    @app_commands.describe(action="การกระทำ", user="สมาชิก (ไม่ต้องระบุถ้าเลือก list)")
    @app_commands.choices(action=[
        app_commands.Choice(name="เพิ่ม", value="add"),
        app_commands.Choice(name="ลบ", value="remove"),
        app_commands.Choice(name="ดูรายชื่อ", value="list"),
    ])
    @app_commands.checks.has_permissions(manage_guild=True)
    async def exempt_cmd(self, interaction: discord.Interaction, action: app_commands.Choice[str], user: discord.Member | None = None) -> None:
        guild = interaction.guild
        assert guild is not None
        rec = self.store.get(guild.id)
        if not rec:
            await interaction.response.send_message("ยังไม่ได้ตั้งค่า — ใช้ `/security setup` ก่อน", ephemeral=True)
            return
        ids: list[int] = list(rec.get("exempt_user_ids", []))
        if action.value == "list":
            text = "\n".join(f"• <@{i}>" for i in ids) or "ยังไม่มี (แอดมิน/ผู้มีสิทธิ์ Manage Server ถูกยกเว้นอยู่แล้ว)"
            await interaction.response.send_message(text, ephemeral=True, allowed_mentions=discord.AllowedMentions.none())
            return
        if user is None:
            await interaction.response.send_message("กรุณาระบุสมาชิก", ephemeral=True)
            return
        if action.value == "add" and user.id not in ids:
            ids.append(user.id)
        elif action.value == "remove" and user.id in ids:
            ids.remove(user.id)
        self.store.update(guild.id, exempt_user_ids=ids)
        log.info("exempt %s user=%s (guild=%s)", action.value, user.id, guild.id)
        await interaction.response.send_message(f"✅ อัปเดตแล้ว: {user.mention}", ephemeral=True, allowed_mentions=discord.AllowedMentions.none())

    async def cog_app_command_error(self, interaction: discord.Interaction, error: app_commands.AppCommandError) -> None:
        if isinstance(error, app_commands.MissingPermissions):
            msg = "คุณต้องมีสิทธิ์ Manage Server เพื่อใช้คำสั่งนี้"
        else:
            log.exception("คำสั่ง Security ผิดพลาด", exc_info=error)
            msg = "เกิดข้อผิดพลาดภายใน ดู Log ของบอท"
        if interaction.response.is_done():
            await interaction.followup.send(msg, ephemeral=True)
        else:
            await interaction.response.send_message(msg, ephemeral=True)


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(SecurityGuard(bot))
