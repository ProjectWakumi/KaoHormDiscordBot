# 🌸 KaoHorm Discord Bot

## ติดตั้ง
```bash
pip install -r requirements.txt
cp .env.example .env     # Windows: copy .env.example .env  แล้วใส่ DISCORD_TOKEN
python main.py
```
ไม่ต้องเปิด Privileged Intents ใน Developer Portal

เชิญบอทด้วยสิทธิ์: View Channels, Send Messages, Read Message History, Embed Links,
Attach Files, Manage Channels, Manage Messages (ไม่ต้องใช้ Administrator)
และ scope `bot` + `applications.commands`

## คำสั่ง (ต้องมีสิทธิ์ Manage Server)
| คำสั่ง | หน้าที่ |
|---|---|
| `/security setup` | สร้าง/ใช้ห้อง Security Guard เดิม + ส่งประกาศ + เปิดระบบ |
| `/security status` | ดูสถานะ ห้อง ประกาศ สิทธิ์บอท |
| `/security repair` | ซ่อมห้องและประกาศ (ไม่เปลี่ยนสถานะเปิด/ปิด) |
| `/security toggle` | เปิด/ปิดระบบ |
| `/security exempt` | เพิ่ม/ลบ/ดูผู้ได้รับการยกเว้น |

## บันทึกเวอร์ชัน + Push GitHub
```bash
python save.py --dry-run   # วิเคราะห์อย่างเดียว
python save.py             # หรือ Save (Windows ใช้ Save.bat)
```
ครั้งแรกต้อง `git init`, `git remote add origin https://github.com/ProjectWakumi/KaoHormDiscordBot.git`
