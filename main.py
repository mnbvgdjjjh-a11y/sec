# ══════════════════════════════════════════════════════════════════
#  Security Bot  –  Full Refactor v2.0
#  pip install discord.py aiohttp
#
#  ENV:
#    DISCORD_TOKEN  – token บอท
#    API_BASE_URL   – URL เว็บ (เช่น https://yourapp.railway.app)
#    PORT           – port web server (default 8080)
#    DATA_SERVER_ID – ID ของ Server หลักที่เก็บข้อมูลทุก guild
# ══════════════════════════════════════════════════════════════════

import os, json, asyncio, io, secrets, logging, re, time
from datetime import datetime, timezone, timedelta
from collections import defaultdict
import discord
from discord import app_commands
from discord.ext import tasks
from aiohttp import web

# ── ENV ────────────────────────────────────────────────────────────
BOT_TOKEN      = os.environ.get("DISCORD_TOKEN", "")
API_BASE_URL   = os.environ.get("API_BASE_URL", "http://localhost:8080")
PORT           = int(os.environ.get("PORT", "8080"))
DATA_SERVER_ID = int(os.environ.get("DATA_SERVER_ID", "0"))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("SecurityBot")

# ── REGEX ──────────────────────────────────────────────────────────
RE_LINK   = re.compile(r"https?://\S+", re.I)
RE_INVITE = re.compile(r"discord(?:\.gg|app\.com/invite)/\S+", re.I)

# ── DANGEROUS PERMISSIONS ──────────────────────────────────────────
DANGEROUS_PERMS = [
    "administrator", "manage_guild", "manage_roles",
    "manage_channels", "ban_members", "kick_members",
    "mention_everyone", "manage_webhooks",
]

# ══════════════════════════════════════════════════════════════════
#  BOT
# ══════════════════════════════════════════════════════════════════
intents = discord.Intents.all()

class SecurityBot(discord.Client):
    def __init__(self):
        super().__init__(intents=intents)
        self.tree = app_commands.CommandTree(self)
        self.guild_data: dict    = {}
        self.active_tokens: dict = {}
        self.data_lock            = asyncio.Lock()
        # per-user spam heat: uid → [timestamp, ...]
        self.heat: dict           = defaultdict(list)
        # per-guild save locks to avoid one slow guild blocking others
        self._save_locks: dict    = defaultdict(asyncio.Lock)
        # guilds currently in raid mode
        self.raid_mode: set       = set()
        # nuke tracking: guild_id → user_id → [(action, ts)]
        self.nuke_track: dict     = defaultdict(lambda: defaultdict(list))
        # voice abuse: guild_id → user_id → [(action, ts)]
        self.voice_track: dict    = defaultdict(lambda: defaultdict(list))
        # attachment spam: guild_id → user_id → [ts]
        self.att_track: dict      = defaultdict(lambda: defaultdict(list))
        # mention spam: guild_id → user_id → [ts]
        self.mention_track: dict  = defaultdict(lambda: defaultdict(list))
        # reaction spam: guild_id → user_id → [ts]
        self.react_track: dict    = defaultdict(lambda: defaultdict(list))
        # link spam: guild_id → user_id → [ts]
        self.link_track: dict     = defaultdict(lambda: defaultdict(list))
        # lockdown: guild_id → {channel_id: old_perms}
        self.lockdown_state: dict = {}
        # vanity url cache
        self.vanity_cache: dict   = {}
        # in-memory audit log
        self.audit_log: dict      = defaultdict(list)
        # suspicious behavior alerts: guild_id → [alert_dict, ...]
        self.suspicious_alerts: dict = defaultdict(list)
        # member action history for deep analysis: guild_id → user_id → [action_dict]
        self.member_actions: dict = defaultdict(lambda: defaultdict(list))
        # advanced lockdown: guild_id → {role_id: original_permissions_value}
        self.adv_lock_state: dict = {}
        # advanced lockdown status: guild_id → bool (is active)
        self.adv_lock_active: set = set()

bot = SecurityBot()

# ══════════════════════════════════════════════════════════════════
#  DEFAULT CONFIG
# ══════════════════════════════════════════════════════════════════
def _feature(punishment="ban", limit=3, window=10, **extra):
    base = {"enabled": False, "limit": limit, "window": window, "punishment": punishment}
    base.update(extra)
    return base

def default_config():
    return {
        # ── AutoMod ──
        "automod": {
            "enabled":        False,
            "banned_words":   [],
            "filter_links":   False,
            "filter_invites": False,
            "filter_caps":    False,
            "filter_emoji":   False,
            "bypass_roles":   [],
            "punishment":     "timeout",
            "mute_duration":  5,
        },

        # ── Anti-Nuke (per-feature, granular) ──
        "anti_ban":        _feature("ban",      limit=3,  window=10),
        "anti_kick":       _feature("ban",      limit=3,  window=10),
        "anti_ch_create":  _feature("ban",      limit=3,  window=10),
        "anti_ch_delete":  _feature("ban",      limit=3,  window=10),
        "anti_ch_update":  _feature("ban",      limit=5,  window=10),
        "anti_role_create":_feature("ban",      limit=3,  window=10),
        "anti_role_delete":_feature("ban",      limit=3,  window=10),
        "anti_role_update":_feature("ban",      limit=5,  window=10),
        "anti_role_give":  _feature("ban",      limit=1,  window=30),
        "anti_webhook_create": _feature("ban",  limit=2,  window=10),
        "anti_webhook_delete": _feature("ban",  limit=2,  window=10),
        "anti_bot_add":    _feature("kick",     limit=1,  window=60,
                                    bot_whitelist=[]),
        "anti_guild_update": _feature("ban",    limit=1,  window=30),
        "anti_vanity":     _feature("ban",      limit=1,  window=30),
        "anti_prune":      _feature("ban",      limit=1,  window=60),
        "anti_integration":_feature("ban",      limit=1,  window=30),

        # ── Anti-Raid / Gatekeeper ──
        "anti_join_flood": _feature("kick",     limit=10, window=60),
        "anti_account_age":_feature("kick",     limit=7,  window=0),   # limit = min days
        "anti_no_avatar":  _feature("kick",     limit=1,  window=0),
        "server_lockdown": {"enabled": False},

        # ── Anti-Spam ──
        "anti_mass_mentions": _feature("timeout", limit=5,  window=10),
        "anti_text_spam":     _feature("timeout", limit=5,  window=5),
        "anti_link_spam":     _feature("timeout", limit=3,  window=10),
        "anti_att_spam":      _feature("timeout", limit=3,  window=10),
        "anti_emoji_spam":    _feature("timeout", limit=3,  window=10),

        # ── Legacy / extra features ──
        "voiceabuse": {
            "enabled":       False,
            "limit":         5,
            "window":        10,
            "punishment":    "timeout",
            "mute_duration": 10,
        },

        # ── General ──
        "whitelist": {"users": [], "roles": []},
        "blacklist_role_id": None,
        "log_channel_id":    None,
        "log_channels": {
            "member_join":    None, "member_leave":  None,
            "member_ban":     None, "member_kick":   None,
            "message_delete": None, "message_edit":  None,
            "role_update":    None, "channel_update":None,
            "voice_update":   None, "invite_create": None,
        },
        "welcome": {
            "enabled":    False,
            "channel_id": None,
            "message":    "ยินดีต้อนรับ {user} สู่ {server}! 🎉",
        },
        "verification": {"enabled": False, "verified_role_id": None},
    }

def get_cfg(guild_id: int) -> dict:
    if guild_id not in bot.guild_data:
        bot.guild_data[guild_id] = default_config()
    else:
        # Fill missing keys from default without overwriting existing
        def _fill(dst, src):
            for k, v in src.items():
                if k not in dst:
                    dst[k] = v
                elif isinstance(v, dict) and isinstance(dst.get(k), dict):
                    _fill(dst[k], v)
        _fill(bot.guild_data[guild_id], default_config())
    return bot.guild_data[guild_id]

def is_whitelisted(member: discord.Member, cfg: dict) -> bool:
    if member.id == member.guild.owner_id:
        return True
    wl = cfg.get("whitelist", {})
    if member.id in [int(x) for x in wl.get("users", []) if x]:
        return True
    member_role_ids = {r.id for r in member.roles}
    if any(int(r) in member_role_ids for r in wl.get("roles", []) if r):
        return True
    # Per-member exemption: "all" = bypass everything
    ex = cfg.get("member_exemptions", {}).get(str(member.id), {})
    if ex.get("all"):
        return True
    return False

def is_exempt(member: discord.Member, cfg: dict, key: str) -> bool:
    """Check if a member is exempt from a specific protection (e.g. 'spam', 'nuke')."""
    if is_whitelisted(member, cfg):
        return True
    ex = cfg.get("member_exemptions", {}).get(str(member.id), {})
    return bool(ex.get(key, False))

# ── Suspicious Behavior Tracker ──────────────────────────────────
SUSPICIOUS_RULES = [
    # (key, description_th, severity, window_sec, threshold)
    ("ch_delete",   "ลบห้องหลายห้องในเวลาสั้น",          "high",   60,  3),
    ("ch_create",   "สร้างห้องจำนวนมากในเวลาสั้น",        "high",   60,  5),
    ("role_give",   "แจกยศอันตรายหลายครั้ง",              "high",   60,  3),
    ("role_delete", "ลบยศหลายอันในเวลาสั้น",              "high",   60,  3),
    ("ban",         "แบนสมาชิกหลายคนในเวลาสั้น",          "high",   60,  3),
    ("kick",        "เตะสมาชิกหลายคนในเวลาสั้น",          "high",   60,  5),
    ("mention",     "แท็กสมาชิก/everyone จำนวนมาก",       "medium", 30,  5),
    ("webhook",     "สร้าง/ลบ Webhook ซ้ำหลายครั้ง",      "medium", 60,  3),
    ("voice_move",  "ย้ายคนใน Voice ซ้ำหลายครั้ง",        "medium", 30,  5),
    ("msg_delete",  "ลบข้อความจำนวนมากในเวลาสั้น",        "low",    30,  10),
]

def record_action(guild_id: int, user_id: int, action_key: str, detail: str = ""):
    now = time.time()
    entry = {"key": action_key, "ts": now, "detail": detail}
    bot.member_actions[guild_id][user_id].append(entry)
    # Keep only last 500 actions per member
    if len(bot.member_actions[guild_id][user_id]) > 500:
        bot.member_actions[guild_id][user_id] = bot.member_actions[guild_id][user_id][-500:]

    # Check each suspicious rule
    for key, desc, severity, window, threshold in SUSPICIOUS_RULES:
        if key != action_key:
            continue
        recent = [e for e in bot.member_actions[guild_id][user_id]
                  if e["key"] == key and now - e["ts"] <= window]
        if len(recent) >= threshold:
            # Avoid duplicate alert within 5 min
            existing = bot.suspicious_alerts[guild_id]
            five_min_ago = now - 300
            already = any(
                a["user_id"] == user_id and a["key"] == key and a["ts"] > five_min_ago
                for a in existing
            )
            if not already:
                bot.suspicious_alerts[guild_id].append({
                    "id":       f"{guild_id}-{user_id}-{key}-{int(now)}",
                    "user_id":  user_id,
                    "key":      key,
                    "desc":     desc,
                    "severity": severity,
                    "ts":       now,
                    "count":    len(recent),
                    "window":   window,
                    "detail":   detail,
                    "read":     False,
                })
                # Keep only last 200 alerts per guild
                if len(bot.suspicious_alerts[guild_id]) > 200:
                    bot.suspicious_alerts[guild_id] = bot.suspicious_alerts[guild_id][-200:]

# ══════════════════════════════════════════════════════════════════
#  AUDIT LOG (in-memory)
# ══════════════════════════════════════════════════════════════════
def add_audit(guild_id: int, action: str, user: str, target: str, reason: str):
    entry = {
        "action":    action,
        "user":      user,
        "target":    target,
        "reason":    reason,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    lst = bot.audit_log[guild_id]
    lst.insert(0, entry)
    # เก็บสูงสุด 500 รายการ
    if len(lst) > 500:
        del lst[500:]

# ══════════════════════════════════════════════════════════════════
#  PUNISHMENT HELPER
# ══════════════════════════════════════════════════════════════════
PUNISH_OPTIONS = ["ban", "kick", "quarantine", "timeout", "log"]

async def apply_punishment(guild: discord.Guild, member: discord.Member,
                           punishment: str, reason: str, mute_min: int = 5):
    cfg = get_cfg(guild.id)
    add_audit(guild.id, punishment.upper(), str(member), str(member.id), reason)
    for attempt in range(3):  # retry up to 3 times on rate limit
        try:
            if punishment == "ban":
                await guild.ban(member, reason=reason, delete_message_days=0)
            elif punishment == "kick":
                await member.kick(reason=reason)
            elif punishment == "timeout":
                await member.timeout(timedelta(minutes=mute_min), reason=reason)
            elif punishment == "quarantine":
                # Strip all roles
                try:
                    await member.edit(roles=[], reason=reason)
                except discord.Forbidden:
                    pass
                bl_id = cfg.get("blacklist_role_id")
                if bl_id:
                    bl_role = guild.get_role(int(bl_id))
                    if bl_role:
                        try:
                            await member.add_roles(bl_role, reason=reason)
                        except discord.Forbidden:
                            pass
            elif punishment == "log":
                pass  # log only
            return  # success
        except discord.Forbidden:
            log.warning(f"apply_punishment Forbidden: {member} | {punishment}")
            return  # no point retrying forbidden
        except discord.HTTPException as e:
            if e.status == 429:
                retry_after = getattr(e, "retry_after", 1.0) or 1.0
                log.warning(f"Rate limited on punishment: retry in {retry_after:.1f}s")
                await asyncio.sleep(retry_after + 0.5)
                # loop will retry
            else:
                log.error(f"apply_punishment HTTPException: {e}")
                return
        except Exception as e:
            log.error(f"apply_punishment error: {e}")
            return

# ══════════════════════════════════════════════════════════════════
#  DATA CHANNEL SYSTEM
# ══════════════════════════════════════════════════════════════════
DATA_CH_PREFIX = "💾・"

async def get_data_server() -> discord.Guild | None:
    if not DATA_SERVER_ID:
        return None
    return bot.get_guild(DATA_SERVER_ID)

async def ensure_data_channel(guild_id: int) -> discord.TextChannel | None:
    ds = await get_data_server()
    if not ds:
        log.warning("DATA_SERVER_ID ไม่ถูกต้องหรือบอทไม่ได้อยู่ใน server นั้น")
        return None
    ch_name = f"{DATA_CH_PREFIX}{guild_id}"
    for ch in ds.text_channels:
        if ch.name == ch_name:
            return ch
    try:
        ow = {
            ds.default_role: discord.PermissionOverwrite(read_messages=False),
            ds.me: discord.PermissionOverwrite(read_messages=True, send_messages=True, manage_messages=True),
        }
        ch = await ds.create_text_channel(ch_name, overwrites=ow, reason="Security Bot: data channel")
        log.info(f"✅ สร้างห้อง {ch_name} ใน {ds.name}")
        return ch
    except Exception as e:
        log.error(f"❌ สร้างห้องไม่ได้: {e}")
        return None

async def load_guild_data(guild_id: int):
    try:
        ch = await ensure_data_channel(guild_id)
        if not ch:
            return
        # ดึงประวัติสูงสุด 50 ข้อความ (purge เก็บไว้แค่ 1 แต่อาจมีเก่าค้างอยู่)
        async for msg in ch.history(limit=50):
            for att in msg.attachments:
                if att.filename == "data.json":
                    try:
                        raw = await att.read()
                        bot.guild_data[guild_id] = json.loads(raw.decode())
                        log.info(f"✅ โหลดข้อมูล guild {guild_id}")
                    except Exception as parse_err:
                        log.error(f"❌ parse data guild {guild_id}: {parse_err}")
                    return  # หยุดหลังเจอไฟล์ล่าสุด
    except Exception as e:
        log.error(f"❌ โหลดข้อมูล guild {guild_id}: {e}")

async def save_guild_data(guild_id: int):
    async with bot._save_locks[guild_id]:
        try:
            ch = await ensure_data_channel(guild_id)
            if not ch:
                return
            await ch.purge(limit=20, check=lambda m: m.author == bot.user)
            raw = json.dumps(get_cfg(guild_id), ensure_ascii=False, indent=2)
            f = discord.File(io.BytesIO(raw.encode()), filename="data.json")
            await ch.send(f"💾 guild:{guild_id}", file=f)
        except Exception as e:
            log.error(f"❌ บันทึก guild {guild_id}: {e}")

@tasks.loop(minutes=5)
async def auto_save():
    for guild in bot.guilds:
        try:
            await save_guild_data(guild.id)
        except Exception as e:
            log.error(f"[auto_save] guild {guild.id}: {e}")

# ══════════════════════════════════════════════════════════════════
#  TOKEN MANAGER
# ══════════════════════════════════════════════════════════════════
def create_token(guild_id: int, guild_name: str) -> str:
    for t, v in list(bot.active_tokens.items()):
        if v["guild_id"] == guild_id:
            del bot.active_tokens[t]
    token = secrets.token_urlsafe(24)
    bot.active_tokens[token] = {
        "guild_id":   guild_id,
        "guild_name": guild_name,
        "expires_at": datetime.now(timezone.utc) + timedelta(minutes=10),
    }
    return token

def verify_token(token: str) -> dict | None:
    d = bot.active_tokens.get(token)
    if not d:
        return None
    if datetime.now(timezone.utc) > d["expires_at"]:
        del bot.active_tokens[token]
        return None
    d["expires_at"] = datetime.now(timezone.utc) + timedelta(minutes=10)
    return d

@tasks.loop(minutes=1)
async def cleanup_tokens():
    now = datetime.now(timezone.utc)
    for t in [t for t, v in list(bot.active_tokens.items()) if now > v["expires_at"]]:
        del bot.active_tokens[t]

# ══════════════════════════════════════════════════════════════════
#  LOGS
# ══════════════════════════════════════════════════════════════════
async def send_log(guild: discord.Guild, embed: discord.Embed, log_type: str = None):
    cfg = get_cfg(guild.id)
    channels_to_send = []
    if log_type:
        specific_id = cfg.get("log_channels", {}).get(log_type)
        if specific_id:
            ch = guild.get_channel(int(specific_id))
            if ch:
                channels_to_send.append(ch)
    main_id = cfg.get("log_channel_id")
    if main_id:
        ch = guild.get_channel(int(main_id))
        if ch and ch not in channels_to_send:
            channels_to_send.append(ch)
    embed.timestamp = datetime.now(timezone.utc)
    for ch in channels_to_send:
        try:
            await ch.send(embed=embed)
        except Exception:
            pass

async def create_log_channel(guild: discord.Guild, log_type: str) -> discord.TextChannel | None:
    names = {
        "member_join":    "📥・log-เข้าร่วม",
        "member_leave":   "📤・log-ออกจาก",
        "member_ban":     "🔨・log-แบน",
        "member_kick":    "👢・log-เตะ",
        "message_delete": "🗑・log-ลบข้อความ",
        "message_edit":   "✏️・log-แก้ข้อความ",
        "role_update":    "🏷️・log-ยศ",
        "channel_update": "📢・log-ช่อง",
        "voice_update":   "🎙️・log-เสียง",
        "invite_create":  "🔗・log-ลิงก์เชิญ",
    }
    ch_name = names.get(log_type, f"log-{log_type}")
    for ch in guild.text_channels:
        if ch.name == ch_name:
            return ch
    try:
        category = discord.utils.get(guild.categories, name="SECURITY LOGS")
        if not category:
            category = await guild.create_category("SECURITY LOGS", reason="Security Bot: สร้าง log category")
        ow = {
            guild.default_role: discord.PermissionOverwrite(read_messages=False, send_messages=False),
            guild.me: discord.PermissionOverwrite(read_messages=True, send_messages=True),
        }
        ch = await guild.create_text_channel(ch_name, category=category, overwrites=ow,
                                              reason=f"Security Bot: log channel for {log_type}")
        log.info(f"✅ สร้างห้อง {ch_name} ใน {guild.name}")
        return ch
    except Exception as e:
        log.error(f"❌ สร้างห้อง log ไม่ได้: {e}")
        return None

# ══════════════════════════════════════════════════════════════════
#  NUKE TRACKER — per-feature, per-user
# ══════════════════════════════════════════════════════════════════
async def check_feature(guild: discord.Guild, actor: discord.Member | discord.User,
                        feature_key: str, label: str):
    """ตรวจสอบว่า actor ทำเกินกำหนดของ feature_key หรือไม่ ถ้าใช่ลงโทษทันที"""
    if actor is None or actor.bot:
        return
    member = guild.get_member(actor.id)
    if member is None:
        # Try fetching if not in cache
        try:
            member = await guild.fetch_member(actor.id)
        except Exception:
            return
    cfg = get_cfg(guild.id)
    feat = cfg.get(feature_key, {})
    if not feat.get("enabled"):
        return
    if is_whitelisted(member, cfg):
        return

    now    = datetime.now(timezone.utc).timestamp()
    window = max(feat.get("window", 10), 1)  # ต้องอย่างน้อย 1 วินาที ไม่งั้น track จะว่างเสมอ
    limit  = feat.get("limit",  3)

    track_key = f"{feature_key}:{actor.id}"
    track = bot.nuke_track[guild.id][track_key]
    track = [t for t in track if now - t < window]
    track.append(now)
    bot.nuke_track[guild.id][track_key] = track

    if len(track) >= limit:
        bot.nuke_track[guild.id][track_key] = []
        # ── ตรวจสอบว่าเปิดโหมดจัดการขั้นสูงหรือไม่ ──
        adv_enabled = cfg.get("advanced_mode", {}).get(feature_key, False)
        if adv_enabled:
            # โหมดขั้นสูง: ปิด permission ก่อน → ตรวจ audit → ลงโทษ → คืน
            # ส่ง actor.id ตรงๆ เพื่อให้ลงโทษได้ทันทีโดยไม่ต้องรอ Audit Log
            asyncio.create_task(do_advanced_lockdown(guild, feature_key, cfg, known_offender_id=actor.id))
            em = discord.Embed(
                title=f"🟣 {label} — โหมดจัดการขั้นสูง",
                description=(
                    f"เกิน {limit}x ใน {window}วิ\nปิดสิทธิ์ผู้ดูแลชั่วคราว กำลังตรวจสอบ..."
                ),
                color=0xa855f7,
            )
            em.set_footer(text=f"Feature: {feature_key} | AdvancedMode ON")
            await send_log(guild, em)
        else:
            # โหมดปกติ: ลงโทษตรงๆ
            punishment = feat.get("punishment", "ban")
            reason = f"{label}: เกิน {limit}x ใน {window}วิ"
            await apply_punishment(guild, member, punishment, reason)
            em = discord.Embed(
                title=f"🚨 {label} ทำงาน",
                description=f"{member.mention} ถูก **{punishment}** ({limit}x ใน {window}วิ)\nเหตุผล: {reason}",
                color=0xf85149,
            )
            em.set_footer(text=f"Feature: {feature_key} | Guild: {guild.id}")
            await send_log(guild, em)

# ══════════════════════════════════════════════════════════════════
#  EVENTS — READY / GUILD JOIN
# ══════════════════════════════════════════════════════════════════
@bot.event
async def on_ready():
    log.info(f"🤖 {bot.user} ออนไลน์")
    ds = await get_data_server()
    if ds:
        log.info(f"📦 Data server: {ds.name} ({ds.id})")
    else:
        log.warning("⚠️  DATA_SERVER_ID ไม่ได้ตั้งค่า")
    for guild in bot.guilds:
        await load_guild_data(guild.id)
        # cache vanity url
        try:
            vanity = await guild.vanity_invite()
            if vanity:
                bot.vanity_cache[guild.id] = vanity.code
        except Exception:
            pass
    if not auto_save.is_running():
        auto_save.start()
    if not cleanup_tokens.is_running():
        cleanup_tokens.start()
    # Sync slash commands globally
    try:
        synced = await bot.tree.sync()
        log.info(f"✅ Synced {len(synced)} slash commands")
    except Exception as e:
        log.error(f"❌ Slash command sync failed: {e}")
    log.info(f"✅ พร้อมใช้งาน — {len(bot.guilds)} server(s)")

@bot.event
async def on_guild_join(guild: discord.Guild):
    log.info(f"📥 เข้า server: {guild.name}")
    await ensure_data_channel(guild.id)
    await save_guild_data(guild.id)

# ══════════════════════════════════════════════════════════════════
#  SLASH COMMANDS (/getcode /initbl /lockdown /whitelist)
# ══════════════════════════════════════════════════════════════════

@bot.tree.command(name="getcode", description="รับรหัสเข้า Dashboard (เจ้าของ Server เท่านั้น)")
async def slash_getcode(interaction: discord.Interaction):
    guild = interaction.guild
    if not guild:
        await interaction.response.send_message("❌ ใช้ได้ใน Server เท่านั้น", ephemeral=True)
        return
    if guild.owner_id != interaction.user.id:
        await interaction.response.send_message("❌ เฉพาะเจ้าของ Server เท่านั้น", ephemeral=True)
        return
    token = create_token(guild.id, guild.name)
    try:
        embed = discord.Embed(
            title="🔐 รหัสเข้าสู่ระบบ Security Bot",
            color=0x3b6ef8,
        )
        embed.add_field(name="รหัส (คลิกเพื่อคัดลอก)", value=f"```{token}```", inline=False)
        embed.add_field(name="⏰ หมดอายุใน", value="10 นาที", inline=True)
        embed.add_field(name="🌐 เว็บ Dashboard", value=f"[เปิดเว็บ]({API_BASE_URL})", inline=True)
        embed.set_footer(text="ห้ามแชร์รหัสนี้ให้ใคร!")
        await interaction.user.send(embed=embed)
        await interaction.response.send_message("📨 ส่ง DM ให้คุณแล้วครับ 🔐", ephemeral=True)
    except discord.Forbidden:
        await interaction.response.send_message("❌ ไม่สามารถส่ง DM ได้ กรุณาเปิดรับ DM ก่อน", ephemeral=True)


@bot.tree.command(name="initbl", description="สร้างยศ Blacklist สำหรับ Quarantine อัตโนมัติ (เจ้าของ Server เท่านั้น)")
async def slash_initbl(interaction: discord.Interaction):
    guild = interaction.guild
    if not guild:
        await interaction.response.send_message("❌ ใช้ได้ใน Server เท่านั้น", ephemeral=True)
        return
    if guild.owner_id != interaction.user.id:
        await interaction.response.send_message("❌ เฉพาะเจ้าของ Server เท่านั้น", ephemeral=True)
        return
    await interaction.response.defer(ephemeral=True)
    cfg = get_cfg(guild.id)
    existing_id = cfg.get("blacklist_role_id")
    if existing_id:
        existing = guild.get_role(int(existing_id))
        if existing:
            await interaction.followup.send(f"✅ ยศ Blacklist มีอยู่แล้ว: **{existing.name}**", ephemeral=True)
            return
    try:
        bl_role = await guild.create_role(name="⛔ Blacklist", color=discord.Color.from_rgb(139, 0, 0),
                                          reason="Security Bot: สร้างยศ Blacklist")
        for channel in guild.channels:
            try:
                await channel.set_permissions(bl_role, view_channel=False, send_messages=False,
                                              connect=False, speak=False, reason="Blacklist role")
            except Exception:
                pass
        cfg["blacklist_role_id"] = bl_role.id
        await save_guild_data(guild.id)
        await interaction.followup.send(f"✅ สร้างยศ **{bl_role.name}** แล้ว\n🆔 Role ID: `{bl_role.id}`", ephemeral=True)
    except Exception as e:
        await interaction.followup.send(f"❌ สร้างยศไม่ได้: {e}", ephemeral=True)


@bot.tree.command(name="lockdown", description="เปิด/ปิด Server Lockdown ฉุกเฉิน (เจ้าของ Server เท่านั้น)")
@app_commands.describe(action="เลือก on เพื่อล็อก หรือ off เพื่อปลดล็อก")
@app_commands.choices(action=[
    app_commands.Choice(name="🔒 เปิด Lockdown", value="on"),
    app_commands.Choice(name="🔓 ปิด Lockdown",  value="off"),
])
async def slash_lockdown(interaction: discord.Interaction, action: str = "on"):
    guild = interaction.guild
    if not guild:
        await interaction.response.send_message("❌ ใช้ได้ใน Server เท่านั้น", ephemeral=True)
        return
    if guild.owner_id != interaction.user.id:
        await interaction.response.send_message("❌ เฉพาะเจ้าของ Server เท่านั้น", ephemeral=True)
        return
    await interaction.response.defer(ephemeral=True)
    enable = action not in ("off", "ปิด", "unlock")
    await do_lockdown(guild, enable)
    cfg = get_cfg(guild.id)
    cfg["server_lockdown"]["enabled"] = enable
    await save_guild_data(guild.id)
    await interaction.followup.send(f"{'🔒 เปิด' if enable else '🔓 ปิด'} Server Lockdown แล้ว", ephemeral=True)


@bot.tree.command(name="whitelist", description="จัดการ Whitelist (เจ้าของ Server เท่านั้น)")
@app_commands.describe(
    action="เพิ่มหรือลบ",
    target_type="ประเภท: user หรือ role",
    member="สมาชิกที่ต้องการ (ถ้า target_type=user)",
    role="ยศที่ต้องการ (ถ้า target_type=role)",
)
@app_commands.choices(
    action=[
        app_commands.Choice(name="เพิ่ม", value="add"),
        app_commands.Choice(name="ลบ",   value="remove"),
        app_commands.Choice(name="ดูรายชื่อ", value="list"),
    ],
    target_type=[
        app_commands.Choice(name="👤 User (สมาชิก)", value="user"),
        app_commands.Choice(name="🏷️ Role (ยศ)",    value="role"),
    ],
)
async def slash_whitelist(
    interaction: discord.Interaction,
    action: str,
    target_type: str = "user",
    member: discord.Member = None,
    role: discord.Role = None,
):
    guild = interaction.guild
    if not guild:
        await interaction.response.send_message("❌ ใช้ได้ใน Server เท่านั้น", ephemeral=True)
        return
    if guild.owner_id != interaction.user.id:
        await interaction.response.send_message("❌ เฉพาะเจ้าของ Server เท่านั้น", ephemeral=True)
        return
    cfg = get_cfg(guild.id)
    wl = cfg.setdefault("whitelist", {"users": [], "roles": []})
    if action == "list":
        user_mentions = [f"<@{uid}>" for uid in wl.get("users", [])]
        role_mentions = [f"<@&{rid}>" for rid in wl.get("roles", [])]
        embed = discord.Embed(title="✅ Whitelist", color=0x3b6ef8)
        embed.add_field(name="👤 สมาชิก", value=", ".join(user_mentions) or "-", inline=False)
        embed.add_field(name="🏷️ ยศ",    value=", ".join(role_mentions) or "-", inline=False)
        await interaction.response.send_message(embed=embed, ephemeral=True)
        return
    if target_type == "user":
        if not member:
            await interaction.response.send_message("❌ กรุณาเลือกสมาชิก", ephemeral=True); return
        if action == "add":
            if member.id not in wl["users"]: wl["users"].append(member.id)
            msg = f"✅ เพิ่ม {member.mention} เข้า Whitelist แล้ว"
        else:
            if member.id in wl["users"]: wl["users"].remove(member.id)
            msg = f"✅ ลบ {member.mention} ออกจาก Whitelist แล้ว"
    else:
        if not role:
            await interaction.response.send_message("❌ กรุณาเลือกยศ", ephemeral=True); return
        if action == "add":
            if role.id not in wl["roles"]: wl["roles"].append(role.id)
            msg = f"✅ เพิ่มยศ {role.mention} เข้า Whitelist แล้ว"
        else:
            if role.id in wl["roles"]: wl["roles"].remove(role.id)
            msg = f"✅ ลบยศ {role.mention} ออกจาก Whitelist แล้ว"
    await save_guild_data(guild.id)
    await interaction.response.send_message(msg, ephemeral=True)


@bot.event
async def on_message(message: discord.Message):
    if message.author.bot or not message.guild:
        return

    guild = message.guild
    cfg   = get_cfg(guild.id)

    if is_whitelisted(message.author, cfg):
        return

    # ── AutoMod ──
    am = cfg["automod"]
    if am["enabled"] and not is_exempt(message.author, cfg, "automod"):
        author_roles = [r.id for r in getattr(message.author, "roles", [])]
        bypass       = [int(r) for r in am.get("bypass_roles", []) if r]
        if not any(r in bypass for r in author_roles):
            content = message.content
            cl      = content.lower()
            for word in am.get("banned_words", []):
                if word and word.lower() in cl:
                    try: await message.delete()
                    except: pass
                    await apply_punishment(guild, message.author, am.get("punishment","timeout"),
                                          "AutoMod: คำต้องห้าม", am.get("mute_duration",5))
                    return
            if am.get("filter_links") and RE_LINK.search(content):
                try: await message.delete()
                except: pass
                await apply_punishment(guild, message.author, am.get("punishment","timeout"),
                                       "AutoMod: ลิงก์", am.get("mute_duration",5))
                return
            if am.get("filter_invites") and RE_INVITE.search(content):
                try: await message.delete()
                except: pass
                await apply_punishment(guild, message.author, am.get("punishment","timeout"),
                                       "AutoMod: invite link", am.get("mute_duration",5))
                return
            if am.get("filter_caps"):
                letters = [c for c in content if c.isalpha()]
                if len(letters) > 8 and sum(1 for c in letters if c.isupper()) / len(letters) > 0.7:
                    try: await message.delete()
                    except: pass
                    await apply_punishment(guild, message.author, am.get("punishment","timeout"),
                                           "AutoMod: caps spam", am.get("mute_duration",5))
                    return

    # ── Anti-Text Spam ──
    if not is_exempt(message.author, cfg, "spam"):
        await _check_text_spam(message, cfg)

    # ── Anti-Mass Mentions ──
    if not is_exempt(message.author, cfg, "mentions"):
        await _check_mass_mentions(message, cfg)

    # ── Anti-Link Spam ──
    if not is_exempt(message.author, cfg, "links"):
        await _check_link_spam(message, cfg)

    # ── Anti-Attachment Spam ──
    if not is_exempt(message.author, cfg, "spam"):
        await _check_att_spam(message, cfg)

    # ── Anti-Emoji Spam ──
    if not is_exempt(message.author, cfg, "spam"):
        await _check_emoji_spam(message, cfg)

# ── Spam sub-functions ──────────────────────────────────────────
def _rate_check(tracker, guild_id, user_id, feat, now):
    """Return (exceeded, track) — synchronous, no I/O."""
    window = feat.get("window", 5)
    limit  = feat.get("limit", 5)
    track  = tracker[guild_id][user_id]
    track  = [t for t in track if now - t < window]
    track.append(now)
    tracker[guild_id][user_id] = track
    return len(track) >= limit, track

async def _check_text_spam(message: discord.Message, cfg: dict):
    feat = cfg.get("anti_text_spam", {})
    if not feat.get("enabled"):
        return
    now  = datetime.now(timezone.utc).timestamp()
    over, _ = _rate_check(bot.heat, message.guild.id, message.author.id, feat, now)
    if over:
        bot.heat[message.guild.id][message.author.id] = []
        await apply_punishment(message.guild, message.author,
                               feat.get("punishment","timeout"), "Anti-Text Spam")
        await send_log(message.guild, discord.Embed(
            title="🔁 Anti-Text Spam", color=0xffa502,
            description=f"{message.author.mention} ส่งข้อความถี่เกินไป"))

async def _check_mass_mentions(message: discord.Message, cfg: dict):
    feat = cfg.get("anti_mass_mentions", {})
    if not feat.get("enabled"):
        return
    limit = feat.get("limit", 5)
    total_mentions = len(message.mentions) + len(message.role_mentions)
    if message.mention_everyone:
        total_mentions += 2
    # Always record mention activity for suspicious tracking (even below limit)
    if total_mentions > 0:
        record_action(message.guild.id, message.author.id, "mention",
                      f"แท็ก {total_mentions} ครั้ง{'(@everyone)' if message.mention_everyone else ''}")
    if total_mentions < limit:
        return
    try: await message.delete()
    except: pass
    await apply_punishment(message.guild, message.author,
                           feat.get("punishment","timeout"), f"Anti-Mass Mentions: {total_mentions} mentions")
    await send_log(message.guild, discord.Embed(
        title="📢 Anti-Mass Mentions", color=0xffa502,
        description=f"{message.author.mention} แท็กสมาชิก {total_mentions} ครั้งในข้อความเดียว"))

async def _check_link_spam(message: discord.Message, cfg: dict):
    feat = cfg.get("anti_link_spam", {})
    if not feat.get("enabled"):
        return
    if not (RE_LINK.search(message.content) or RE_INVITE.search(message.content)):
        return
    now  = datetime.now(timezone.utc).timestamp()
    over, _ = _rate_check(bot.link_track, message.guild.id, message.author.id, feat, now)
    if over:
        bot.link_track[message.guild.id][message.author.id] = []
        try: await message.delete()
        except: pass
        await apply_punishment(message.guild, message.author,
                               feat.get("punishment","timeout"), "Anti-Link Spam")
        await send_log(message.guild, discord.Embed(
            title="🔗 Anti-Link Spam", color=0xffa502,
            description=f"{message.author.mention} ส่งลิงก์ถี่เกินไป"))

async def _check_att_spam(message: discord.Message, cfg: dict):
    feat = cfg.get("anti_att_spam", {})
    if not feat.get("enabled") or not message.attachments:
        return
    now  = datetime.now(timezone.utc).timestamp()
    over, _ = _rate_check(bot.att_track, message.guild.id, message.author.id, feat, now)
    if over:
        bot.att_track[message.guild.id][message.author.id] = []
        try: await message.delete()
        except: pass
        await apply_punishment(message.guild, message.author,
                               feat.get("punishment","timeout"), "Anti-Attachment Spam")
        await send_log(message.guild, discord.Embed(
            title="📎 Anti-Attachment Spam", color=0xffa502,
            description=f"{message.author.mention} ส่งไฟล์ถี่เกินไป"))

async def _check_emoji_spam(message: discord.Message, cfg: dict):
    feat = cfg.get("anti_emoji_spam", {})
    if not feat.get("enabled"):
        return
    limit = feat.get("limit", 10)
    # นับ custom emoji (<:name:id> และ animated <a:name:id>) + unicode emoji (codepoint ≥ 0x1F300)
    custom_emoji = message.content.count("<:") + message.content.count("<a:")
    unicode_emoji = sum(1 for c in message.content if ord(c) >= 0x1F300)
    emoji_count = custom_emoji + unicode_emoji
    if emoji_count < limit:
        return
    try: await message.delete()
    except: pass
    await apply_punishment(message.guild, message.author,
                           feat.get("punishment","timeout"), f"Anti-Emoji Spam: {emoji_count} emoji")
    await send_log(message.guild, discord.Embed(
        title="😂 Anti-Emoji Spam", color=0xffa502,
        description=f"{message.author.mention} ส่ง emoji {emoji_count} ตัวในข้อความเดียว"))

# ══════════════════════════════════════════════════════════════════
#  REACTION SPAM
# ══════════════════════════════════════════════════════════════════
@bot.event
async def on_reaction_add(reaction: discord.Reaction, user: discord.User):
    if user.bot or not reaction.message.guild:
        return
    guild  = reaction.message.guild
    cfg    = get_cfg(guild.id)
    feat   = cfg.get("anti_emoji_spam", {})
    if not feat.get("enabled"):
        return
    now  = datetime.now(timezone.utc).timestamp()
    over, _ = _rate_check(bot.react_track, guild.id, user.id, feat, now)
    if over:
        bot.react_track[guild.id][user.id] = []
        member = guild.get_member(user.id)
        if member and not is_whitelisted(member, cfg):
            await apply_punishment(guild, member,
                                   feat.get("punishment","timeout"), "Anti-Reaction Spam")

# ══════════════════════════════════════════════════════════════════
#  JOIN GATE + ANTI-RAID + ANTI-JOIN-FLOOD
# ══════════════════════════════════════════════════════════════════
@bot.event
async def on_member_join(member: discord.Member):
    guild = member.guild
    cfg   = get_cfg(guild.id)
    age   = (datetime.now(timezone.utc) - member.created_at).days

    # ── Welcome ──
    wlc = cfg.get("welcome", {})
    if wlc.get("enabled") and wlc.get("channel_id"):
        try:
            ch = guild.get_channel(int(wlc["channel_id"]))
            if ch:
                msg = (wlc.get("message","ยินดีต้อนรับ {user}!")
                       .replace("{user}", member.mention)
                       .replace("{server}", guild.name)
                       .replace("{count}", str(guild.member_count)))
                em = discord.Embed(description=msg, color=0x5865F2)
                em.set_thumbnail(url=member.display_avatar.url)
                await ch.send(embed=em)
        except Exception as e:
            log.error(f"[Welcome] guild {guild.id}: {e}")

    # ── Anti-Account Age ──
    age_feat = cfg.get("anti_account_age", {})
    if age_feat.get("enabled") and not is_exempt(member, cfg, "raid"):
        min_days = age_feat.get("limit", 7)
        if age < min_days:
            try: await member.send(f"❌ บัญชีของคุณอายุน้อยเกินไป ({age} วัน / ต้องการอย่างน้อย {min_days} วัน)")
            except: pass
            await apply_punishment(guild, member, age_feat.get("punishment","kick"),
                                   f"Anti-Account Age: บัญชีอายุ {age} วัน")
            return

    # ── Anti-No Avatar ──
    av_feat = cfg.get("anti_no_avatar", {})
    if av_feat.get("enabled") and member.avatar is None and not is_exempt(member, cfg, "raid"):
        try: await member.send("❌ กรุณาตั้งรูปโปรไฟล์ก่อนเข้าร่วม Server")
        except: pass
        await apply_punishment(guild, member, av_feat.get("punishment","kick"),
                               "Anti-Default Avatar: ไม่มีรูปโปรไฟล์")
        return

    # ── Anti-Bot Add (bot joining via invite) ──
    if member.bot:
        feat = cfg.get("anti_bot_add", {})
        if feat.get("enabled"):
            wl_bots = [int(x) for x in feat.get("bot_whitelist", []) if x]
            if member.id not in wl_bots:
                # find who added the bot
                try:
                    async for entry in guild.audit_logs(limit=5, action=discord.AuditLogAction.bot_add):
                        if entry.target.id == member.id:
                            inviter = guild.get_member(entry.user.id)
                            if inviter and not is_whitelisted(inviter, cfg):
                                await apply_punishment(guild, inviter, feat.get("punishment","kick"),
                                                       f"Anti-Bot Add: เชิญบอท {member} โดยไม่ได้รับอนุญาต")
                            break
                except Exception as e:
                    log.error(f"anti_bot_add audit log error: {e}")
                try: await member.kick(reason="Anti-Bot Add: บอทไม่อยู่ใน whitelist")
                except: pass
        return

    # ── Anti-Join Flood ──
    flood_feat = cfg.get("anti_join_flood", {})
    if flood_feat.get("enabled"):
        now    = datetime.now(timezone.utc).timestamp()
        window = flood_feat.get("window", 60)
        limit  = flood_feat.get("limit", 10)
        bot.join_tracker[guild.id] = [t for t in bot.join_tracker[guild.id] if now - t < window]
        bot.join_tracker[guild.id].append(now)
        if len(bot.join_tracker[guild.id]) >= limit and guild.id not in bot.raid_mode:
            bot.raid_mode.add(guild.id)
            em = discord.Embed(title="🚨 RAID DETECTED",
                               description=f"มีบัญชีเข้าร่วม {limit}+ คนใน {window} วิ — เปิด Raid Mode",
                               color=0xf85149)
            await send_log(guild, em)
            asyncio.create_task(_disable_raid(guild.id))
        if guild.id in bot.raid_mode:
            await apply_punishment(guild, member, flood_feat.get("punishment","kick"),
                                   "Anti-Join Flood: Raid Mode active")
            return

    # ── Log ──
    em = discord.Embed(title="📥 สมาชิกเข้าร่วม", color=0x3fb950)
    em.set_thumbnail(url=member.display_avatar.url)
    em.add_field(name="สมาชิก", value=f"{member.mention} ({member})", inline=False)
    em.add_field(name="อายุบัญชี", value=f"{age} วัน", inline=True)
    em.add_field(name="สมาชิกลำดับที่", value=str(guild.member_count), inline=True)
    await send_log(guild, em, "member_join")

async def _disable_raid(guild_id: int):
    await asyncio.sleep(600)
    bot.raid_mode.discard(guild_id)
    guild = bot.get_guild(guild_id)
    if guild:
        await send_log(guild, discord.Embed(title="✅ Raid Mode ปิดแล้ว", color=0x3fb950))

# ══════════════════════════════════════════════════════════════════
#  SERVER LOCKDOWN
# ══════════════════════════════════════════════════════════════════
async def do_lockdown(guild: discord.Guild, enable: bool):
    cfg = get_cfg(guild.id)
    if enable:
        if guild.id in bot.lockdown_state:
            return
        saved = {}
        for ch in guild.text_channels:
            try:
                old = ch.overwrites_for(guild.default_role)
                saved[ch.id] = {"send_messages": old.send_messages, "add_reactions": old.add_reactions}
                await ch.set_permissions(guild.default_role,
                                         send_messages=False, add_reactions=False,
                                         reason="Server Lockdown")
            except Exception:
                pass
        bot.lockdown_state[guild.id] = saved
        # Disable all active invites
        try:
            for inv in await guild.invites():
                await inv.delete(reason="Server Lockdown")
        except Exception:
            pass
        em = discord.Embed(title="🔒 Server Lockdown เปิดแล้ว",
                           description="ปิดการพิมพ์ทุกห้องและยกเลิกลิงก์เชิญทั้งหมด",
                           color=0xf85149)
        await send_log(guild, em)
    else:
        if guild.id not in bot.lockdown_state:
            return  # ไม่ได้ล็อกอยู่ ไม่ต้องทำอะไร
        saved = bot.lockdown_state.pop(guild.id, {})
        for ch in guild.text_channels:
            try:
                data = saved.get(ch.id, {})
                await ch.set_permissions(guild.default_role,
                                         send_messages=data.get("send_messages"),
                                         add_reactions=data.get("add_reactions"),
                                         reason="Server Lockdown: ยกเลิก")
            except Exception:
                pass
        em = discord.Embed(title="🔓 Server Lockdown ปิดแล้ว",
                           description="คืนสิทธิ์ทุกห้องเรียบร้อยแล้ว",
                           color=0x3fb950)
        await send_log(guild, em)

# ══════════════════════════════════════════════════════════════════
#  ANTI-NUKE EVENTS
# ══════════════════════════════════════════════════════════════════
@bot.event
async def on_member_ban(guild: discord.Guild, user: discord.User):
    em = discord.Embed(title="🔨 แบนสมาชิก", color=0xef4444)
    em.add_field(name="ผู้ถูกแบน", value=f"{user} ({user.id})", inline=False)
    try:
        async for entry in guild.audit_logs(limit=1, action=discord.AuditLogAction.ban):
            em.add_field(name="แบนโดย", value=str(entry.user), inline=True)
            em.add_field(name="เหตุผล", value=entry.reason or "-", inline=True)
            await check_feature(guild, entry.user, "anti_ban", "Anti-Ban")
            record_action(guild.id, entry.user.id, "ban", f"แบน {user} ({user.id})")
    except Exception as e:
        log.error(f"on_member_ban: {e}")
    await send_log(guild, em, "member_ban")

@bot.event
async def on_member_remove(member: discord.Member):
    guild = member.guild
    em = discord.Embed(title="📤 สมาชิกออกจาก Server", color=0xf85149)
    em.set_thumbnail(url=member.display_avatar.url)
    em.add_field(name="สมาชิก", value=f"{member} ({member.id})", inline=False)
    try:
        async for entry in guild.audit_logs(limit=1, action=discord.AuditLogAction.kick):
            if entry.target.id == member.id:
                em.add_field(name="เตะโดย", value=str(entry.user), inline=True)
                await check_feature(guild, entry.user, "anti_kick", "Anti-Kick")
                record_action(guild.id, entry.user.id, "kick", f"เตะ {member} ({member.id})")
    except Exception:
        pass
    await send_log(guild, em, "member_leave")

@bot.event
async def on_member_unban(guild: discord.Guild, user: discord.User):
    em = discord.Embed(title="✅ ยกเลิกแบน", color=0x3fb950)
    em.add_field(name="ผู้ถูกยกเลิกแบน", value=f"{user} ({user.id})", inline=False)
    await send_log(guild, em)

@bot.event
async def on_guild_channel_create(channel: discord.abc.GuildChannel):
    em = discord.Embed(title="📢 สร้างช่องใหม่", color=0x3fb950)
    em.add_field(name="ช่อง", value=channel.name, inline=False)
    try:
        async for entry in channel.guild.audit_logs(limit=1, action=discord.AuditLogAction.channel_create):
            em.add_field(name="สร้างโดย", value=str(entry.user), inline=True)
            await check_feature(channel.guild, entry.user, "anti_ch_create", "Anti-Channel Create")
            record_action(channel.guild.id, entry.user.id, "ch_create", f"สร้างช่อง #{channel.name}")
    except Exception as e:
        log.error(f"on_guild_channel_create: {e}")
    await send_log(channel.guild, em, "channel_update")

@bot.event
async def on_guild_channel_delete(channel: discord.abc.GuildChannel):
    em = discord.Embed(title="🗑️ ลบช่อง", color=0xef4444)
    em.add_field(name="ชื่อช่อง", value=channel.name, inline=False)
    try:
        async for entry in channel.guild.audit_logs(limit=1, action=discord.AuditLogAction.channel_delete):
            em.add_field(name="ลบโดย", value=str(entry.user), inline=True)
            await check_feature(channel.guild, entry.user, "anti_ch_delete", "Anti-Channel Delete")
            record_action(channel.guild.id, entry.user.id, "ch_delete", f"ลบช่อง #{channel.name}")
    except Exception as e:
        log.error(f"on_guild_channel_delete: {e}")
    await send_log(channel.guild, em, "channel_update")

@bot.event
async def on_guild_channel_update(before: discord.abc.GuildChannel, after: discord.abc.GuildChannel):
    try:
        async for entry in before.guild.audit_logs(limit=1, action=discord.AuditLogAction.channel_update):
            await check_feature(before.guild, entry.user, "anti_ch_update", "Anti-Channel Update")
    except Exception as e:
        log.error(f"on_guild_channel_update: {e}")

@bot.event
async def on_guild_role_create(role: discord.Role):
    em = discord.Embed(title="🏷️ สร้างยศใหม่", color=0x3fb950)
    em.add_field(name="ยศ", value=role.name, inline=False)
    try:
        async for entry in role.guild.audit_logs(limit=1, action=discord.AuditLogAction.role_create):
            em.add_field(name="สร้างโดย", value=str(entry.user), inline=True)
            await check_feature(role.guild, entry.user, "anti_role_create", "Anti-Role Create")
    except Exception as e:
        log.error(f"on_guild_role_create: {e}")
    await send_log(role.guild, em, "role_update")

@bot.event
async def on_guild_role_delete(role: discord.Role):
    em = discord.Embed(title="🗑️ ลบยศ", color=0xef4444)
    em.add_field(name="ชื่อยศ", value=role.name, inline=False)
    try:
        async for entry in role.guild.audit_logs(limit=1, action=discord.AuditLogAction.role_delete):
            em.add_field(name="ลบโดย", value=str(entry.user), inline=True)
            await check_feature(role.guild, entry.user, "anti_role_delete", "Anti-Role Delete")
            record_action(role.guild.id, entry.user.id, "role_delete", f"ลบยศ @{role.name}")
    except Exception as e:
        log.error(f"on_guild_role_delete: {e}")
    await send_log(role.guild, em, "role_update")

@bot.event
async def on_guild_role_update(before: discord.Role, after: discord.Role):
    try:
        async for entry in before.guild.audit_logs(limit=1, action=discord.AuditLogAction.role_update):
            await check_feature(before.guild, entry.user, "anti_role_update", "Anti-Role Update")
    except Exception as e:
        log.error(f"on_guild_role_update: {e}")

@bot.event
async def on_member_update(before: discord.Member, after: discord.Member):
    guild = before.guild
    cfg   = get_cfg(guild.id)
    added   = [r for r in after.roles if r not in before.roles]
    removed = [r for r in before.roles if r not in after.roles]

    if added:
        # Anti-Role Give (dangerous permissions)
        feat = cfg.get("anti_role_give", {})
        if feat.get("enabled"):
            for role in added:
                perms = role.permissions
                has_danger = any(getattr(perms, p, False) for p in DANGEROUS_PERMS)
                if has_danger:
                    try:
                        async for entry in guild.audit_logs(limit=1, action=discord.AuditLogAction.member_role_update):
                            await check_feature(guild, entry.user, "anti_role_give", "Anti-Role Give (Dangerous)")
                    except Exception as e:
                        log.error(f"anti_role_give: {e}")
                    break

    if added or removed:
        em = discord.Embed(title="🏷️ ยศสมาชิกเปลี่ยน", color=0x5865F2)
        em.add_field(name="สมาชิก", value=f"{after.mention} ({after})", inline=False)
        if added:   em.add_field(name="ได้รับยศ", value=" ".join(r.mention for r in added),   inline=False)
        if removed: em.add_field(name="ถูกถอดยศ", value=" ".join(r.mention for r in removed), inline=False)
        try:
            async for entry in guild.audit_logs(limit=1, action=discord.AuditLogAction.member_role_update):
                em.add_field(name="โดย", value=str(entry.user), inline=True)
        except Exception:
            pass
        await send_log(guild, em, "role_update")

    if before.nick != after.nick:
        em = discord.Embed(title="✏️ เปลี่ยนชื่อเล่น", color=0x8b5cf6)
        em.add_field(name="สมาชิก", value=f"{after.mention}", inline=False)
        em.add_field(name="ก่อน", value=before.nick or "(ไม่มี)", inline=True)
        em.add_field(name="หลัง", value=after.nick or "(ไม่มี)", inline=True)
        await send_log(guild, em)

# webhook_create / webhook_delete ถูกจับใน on_audit_log_entry_create แล้ว
# on_webhooks_update ถูกลบออกเพื่อป้องกัน double-trigger

@bot.event
async def on_guild_update(before: discord.Guild, after: discord.Guild):
    try:
        async for entry in after.audit_logs(limit=1, action=discord.AuditLogAction.guild_update):
            await check_feature(after, entry.user, "anti_guild_update", "Anti-Guild Update")
    except Exception as e:
        log.error(f"on_guild_update: {e}")

    # Anti-Vanity URL
    cfg = get_cfg(after.id)
    feat = cfg.get("anti_vanity", {})
    if feat.get("enabled"):
        old_vanity = bot.vanity_cache.get(after.id)
        try:
            new_inv = await after.vanity_invite()
            new_code = new_inv.code if new_inv else None
        except Exception:
            new_code = None
        if old_vanity and old_vanity != new_code:
            # Someone changed/removed the vanity URL — restore it
            try:
                await after.edit(vanity_code=old_vanity, reason="Anti-Vanity: ดึง URL กลับ")
            except Exception as e:
                log.error(f"Anti-Vanity restore error: {e}")
            try:
                async for entry in after.audit_logs(limit=1, action=discord.AuditLogAction.guild_update):
                    await check_feature(after, entry.user, "anti_vanity", "Anti-Vanity URL")
            except Exception:
                pass
        else:
            bot.vanity_cache[after.id] = new_code

# integration_create / integration_update ถูกจับใน on_audit_log_entry_create แล้ว

@bot.event
async def on_audit_log_entry_create(entry: discord.AuditLogEntry):
    """
    Catch audit log events that don't have a dedicated discord.py event:
    - member_prune → anti_prune
    - integration_create / integration_update → anti_integration (double-guard)
    """
    guild = entry.guild
    try:
        if entry.action == discord.AuditLogAction.member_prune:
            await check_feature(guild, entry.user, "anti_prune", "Anti-Prune Members")
        elif entry.action in (discord.AuditLogAction.integration_create,
                              discord.AuditLogAction.integration_update):
            await check_feature(guild, entry.user, "anti_integration", "Anti-Integration")
        elif entry.action == discord.AuditLogAction.webhook_create:
            await check_feature(guild, entry.user, "anti_webhook_create", "Anti-Webhook Create")
        elif entry.action == discord.AuditLogAction.webhook_delete:
            await check_feature(guild, entry.user, "anti_webhook_delete", "Anti-Webhook Delete")
    except Exception as e:
        log.error(f"on_audit_log_entry_create: {e}")

# ══════════════════════════════════════════════════════════════════
#  VOICE ABUSE
# ══════════════════════════════════════════════════════════════════
VOICE_ABUSE_ACTIONS = {
    discord.AuditLogAction.member_update,
    discord.AuditLogAction.member_move,
    discord.AuditLogAction.member_disconnect,
}

@bot.event
async def on_voice_state_update(member: discord.Member, before: discord.VoiceState, after: discord.VoiceState):
    guild = member.guild
    cfg   = get_cfg(guild.id)
    va    = cfg.get("voiceabuse", {})
    if not va.get("enabled"):
        return
    try:
        async for entry in guild.audit_logs(limit=1):
            if entry.action not in VOICE_ABUSE_ACTIONS:
                return
            actor = entry.user
            if actor.bot or actor.id == member.id:
                return
            actor_member = guild.get_member(actor.id)
            if actor_member is None:
                return
            if is_whitelisted(actor_member, cfg):
                return
            now      = datetime.now(timezone.utc).timestamp()
            interval = va.get("window", 10)
            limit    = va.get("limit", 5)
            track    = bot.voice_track[guild.id][actor.id]
            track    = [(a, t) for a, t in track if now - t < interval]
            track.append((str(entry.action), now))
            bot.voice_track[guild.id][actor.id] = track
            if len(track) >= limit:
                bot.voice_track[guild.id][actor.id] = []
                mute_min = va.get("mute_duration", 10)
                await apply_punishment(guild, actor_member,
                    va.get("punishment", "timeout"),
                    f"Voice Abuse: {len(track)} ครั้งใน {interval} วิ", mute_min)
                await send_log(guild, discord.Embed(
                    title="🎙️ Voice Abuse",
                    description=f"{actor_member.mention} ทำ voice action รัวๆ ({len(track)}x ใน {interval}วิ)",
                    color=0xf59e0b))
    except Exception as e:
        log.error(f"on_voice_state_update: {e}")

# ══════════════════════════════════════════════════════════════════
#  OTHER LOG EVENTS
# ══════════════════════════════════════════════════════════════════
@bot.event
async def on_message_delete(message: discord.Message):
    if message.author.bot or not message.guild:
        return
    em = discord.Embed(title="🗑️ ลบข้อความ", color=0xd29922)
    em.add_field(name="ผู้ส่ง", value=f"{message.author.mention} ({message.author})", inline=False)
    em.add_field(name="ห้อง", value=message.channel.mention, inline=True)
    em.add_field(name="ข้อความ", value=message.content[:500] or "(ไม่มีข้อความ)", inline=False)
    if message.attachments:
        em.add_field(name="ไฟล์แนบ", value=", ".join(a.filename for a in message.attachments), inline=False)
    await send_log(message.guild, em, "message_delete")

@bot.event
async def on_message_edit(before: discord.Message, after: discord.Message):
    if before.author.bot or before.content == after.content or not before.guild:
        return
    em = discord.Embed(title="✏️ แก้ไขข้อความ", color=0x5865F2)
    em.add_field(name="ผู้ส่ง", value=f"{before.author.mention} ({before.author})", inline=False)
    em.add_field(name="ห้อง", value=before.channel.mention, inline=True)
    em.add_field(name="ก่อน", value=before.content[:300] or "-", inline=False)
    em.add_field(name="หลัง", value=after.content[:300] or "-", inline=False)
    em.add_field(name="ลิงก์", value=f"[ดูข้อความ]({after.jump_url})", inline=True)
    await send_log(before.guild, em, "message_edit")

@bot.event
async def on_invite_create(invite: discord.Invite):
    if not invite.guild:
        return
    em = discord.Embed(title="🔗 สร้างลิงก์เชิญ", color=0x3b82f6)
    em.add_field(name="สร้างโดย", value=str(invite.inviter) if invite.inviter else "Integration/System", inline=True)
    em.add_field(name="ลิงก์", value=invite.url, inline=True)
    em.add_field(name="หมดอายุ", value=f"{invite.max_age//3600} ชั่วโมง" if invite.max_age else "ไม่มีกำหนด", inline=True)
    await send_log(invite.guild, em, "invite_create")

# ══════════════════════════════════════════════════════════════════
#  COMMANDS HELPERS
# ══════════════════════════════════════════════════════════════════
async def cmd_init_blacklist(message: discord.Message):
    guild = message.guild
    cfg   = get_cfg(guild.id)
    existing_id = cfg.get("blacklist_role_id")
    if existing_id:
        existing = guild.get_role(int(existing_id))
        if existing:
            await message.reply(f"✅ ยศ Blacklist มีอยู่แล้ว: **{existing.name}**", delete_after=10)
            return
    try:
        bl_role = await guild.create_role(name="⛔ Blacklist", color=discord.Color.from_rgb(139, 0, 0),
                                          reason="Security Bot: สร้างยศ Blacklist")
        for channel in guild.channels:
            try:
                await channel.set_permissions(bl_role, view_channel=False, send_messages=False,
                                              connect=False, speak=False, reason="Blacklist role")
            except Exception:
                pass
        cfg["blacklist_role_id"] = bl_role.id
        await save_guild_data(guild.id)
        await message.reply(f"✅ สร้างยศ **{bl_role.name}** แล้ว\n🆔 Role ID: `{bl_role.id}`", delete_after=15)
    except Exception as e:
        await message.reply(f"❌ สร้างยศไม่ได้: {e}", delete_after=10)

async def cmd_whitelist(message: discord.Message, cfg: dict):
    parts = message.content.strip().split()
    wl = cfg.setdefault("whitelist", {"users": [], "roles": []})
    if len(parts) < 2:
        await message.reply(
            "📋 วิธีใช้:\n"
            "`!whitelist user @สมาชิก` — เพิ่มสมาชิก\n"
            "`!whitelist role @ยศ` — เพิ่มยศ\n"
            "`!whitelist remove user @สมาชิก` — ลบสมาชิก\n"
            "`!whitelist remove role @ยศ` — ลบยศ\n"
            "`!whitelist list` — ดูรายชื่อ",
            delete_after=20)
        return
    sub = parts[1].lower()
    if sub == "list":
        user_mentions = [f"<@{uid}>" for uid in wl.get("users", [])]
        role_mentions = [f"<@&{rid}>" for rid in wl.get("roles", [])]
        txt = f"📋 **Whitelist**\n👤 สมาชิก: {', '.join(user_mentions) or '-'}\n🏷️ ยศ: {', '.join(role_mentions) or '-'}"
        await message.reply(txt, delete_after=20)
        return
    removing = (sub == "remove")
    if removing and len(parts) >= 3:
        sub = parts[2].lower()
    if sub == "user":
        if not message.mentions:
            await message.reply("❌ กรุณาแท็กสมาชิก", delete_after=5); return
        for m in message.mentions:
            if removing:
                if m.id in wl["users"]: wl["users"].remove(m.id)
                await message.reply(f"✅ ลบ {m.mention} ออกจาก whitelist", delete_after=5)
            else:
                if m.id not in wl["users"]: wl["users"].append(m.id)
                await message.reply(f"✅ เพิ่ม {m.mention} เข้า whitelist", delete_after=5)
    elif sub == "role":
        if not message.role_mentions:
            await message.reply("❌ กรุณาแท็กยศ", delete_after=5); return
        for r in message.role_mentions:
            if removing:
                if r.id in wl["roles"]: wl["roles"].remove(r.id)
                await message.reply(f"✅ ลบยศ {r.mention} ออกจาก whitelist", delete_after=5)
            else:
                if r.id not in wl["roles"]: wl["roles"].append(r.id)
                await message.reply(f"✅ เพิ่มยศ {r.mention} เข้า whitelist", delete_after=5)
    else:
        await message.reply("❌ คำสั่งไม่ถูกต้อง", delete_after=5); return
    await save_guild_data(message.guild.id)

# ══════════════════════════════════════════════════════════════════
#  WEB API
# ══════════════════════════════════════════════════════════════════
CORS = {"Access-Control-Allow-Origin": "*"}

def jres(data, status=200):
    return web.Response(
        text=json.dumps(data, ensure_ascii=False),
        status=status,
        headers={**CORS, "Content-Type": "application/json"},
    )

async def api_options(req):
    return web.Response(status=200, headers={
        **CORS,
        "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
    })

async def api_verify(req):
    t = req.rel_url.query.get("token", "")
    d = verify_token(t)
    if not d: return jres({"valid": False, "message": "รหัสไม่ถูกต้องหรือหมดอายุ"}, 401)
    return jres({"valid": True, "guild_id": str(d["guild_id"]), "guild_name": d["guild_name"]})

async def api_get_config(req):
    t = req.rel_url.query.get("token", "")
    d = verify_token(t)
    if not d: return jres({"error": "unauthorized"}, 401)
    return jres(get_cfg(d["guild_id"]))

async def api_post_config(req):
    t = req.rel_url.query.get("token", "")
    d = verify_token(t)
    if not d: return jres({"error": "unauthorized"}, 401)
    try:
        new = await req.json()
        cfg = get_cfg(d["guild_id"])
        def _deep_merge(dst, src):
            for k, v in src.items():
                if isinstance(v, dict) and isinstance(dst.get(k), dict):
                    _deep_merge(dst[k], v)
                else:
                    dst[k] = v
        _deep_merge(cfg, new)
        # Handle lockdown toggle
        guild = bot.get_guild(d["guild_id"])
        if guild:
            ld = cfg.get("server_lockdown", {})
            ld_active = guild.id in bot.lockdown_state
            if ld.get("enabled") and not ld_active:
                asyncio.create_task(do_lockdown(guild, True))
            elif not ld.get("enabled") and ld_active:
                asyncio.create_task(do_lockdown(guild, False))
        await save_guild_data(d["guild_id"])
        return jres({"success": True})
    except Exception as e:
        return jres({"error": str(e)}, 400)

async def api_stats(req):
    t = req.rel_url.query.get("token", "")
    d = verify_token(t)
    if not d: return jres({"error": "unauthorized"}, 401)
    guild = bot.get_guild(d["guild_id"])
    if not guild: return jres({"error": "guild not found"}, 404)
    online = sum(1 for m in guild.members
                 if not m.bot and getattr(m, "status", discord.Status.offline) != discord.Status.offline)
    return jres({
        "guild_name":    guild.name,
        "server_id":     str(guild.id),
        "member_count":  guild.member_count,
        "online_count":  online,
        "channel_count": len(guild.channels),
        "role_count":    len(guild.roles),
        "icon_url":      str(guild.icon.url) if guild.icon else "",
        "in_lockdown":   guild.id in bot.lockdown_state,
        "raid_mode":     guild.id in bot.raid_mode,
    })

async def api_logs(req):
    t = req.rel_url.query.get("token", "")
    d = verify_token(t)
    if not d: return jres({"error": "unauthorized"}, 401)
    guild = bot.get_guild(d["guild_id"])
    if not guild: return jres({"error": "guild not found"}, 404)
    # ── ดึง internal audit log ทั้งหมด (สูงสุด 200 รายการ) ──
    internal = list(bot.audit_log.get(d["guild_id"], []))
    if internal:
        return jres(internal[:100])
    # ── fallback: ดึง Discord audit logs เมื่อยังไม่มี internal ──
    logs = []
    try:
        async for entry in guild.audit_logs(limit=50):
            logs.append({
                "action":    str(entry.action).replace("AuditLogAction.", ""),
                "user":      str(entry.user),
                "target":    str(entry.target) if entry.target else "-",
                "reason":    entry.reason or "-",
                "timestamp": entry.created_at.isoformat(),
            })
    except Exception as e:
        return jres({"error": str(e)}, 500)
    return jres(logs)

async def api_create_log_channel(req):
    t = req.rel_url.query.get("token", "")
    d = verify_token(t)
    if not d: return jres({"error": "unauthorized"}, 401)
    guild = bot.get_guild(d["guild_id"])
    if not guild: return jres({"error": "guild not found"}, 404)
    try:
        body = await req.json()
        log_type = body.get("log_type", "")
        valid_types = ["member_join","member_leave","member_ban","member_kick",
                       "message_delete","message_edit","role_update","channel_update",
                       "voice_update","invite_create"]
        if log_type not in valid_types:
            return jres({"error": "invalid log_type"}, 400)
        ch = await create_log_channel(guild, log_type)
        if not ch:
            return jres({"error": "สร้างห้องไม่ได้ ตรวจสอบ permission"}, 500)
        cfg = get_cfg(guild.id)
        cfg.setdefault("log_channels", {})[log_type] = ch.id
        await save_guild_data(guild.id)
        return jres({"success": True, "channel_id": str(ch.id), "channel_name": ch.name})
    except Exception as e:
        return jres({"error": str(e)}, 400)

async def api_delete_log_channel(req):
    t = req.rel_url.query.get("token", "")
    d = verify_token(t)
    if not d: return jres({"error": "unauthorized"}, 401)
    try:
        body = await req.json()
        log_type = body.get("log_type", "")
        cfg = get_cfg(d["guild_id"])
        if "log_channels" in cfg and log_type in cfg["log_channels"]:
            cfg["log_channels"][log_type] = None
        await save_guild_data(d["guild_id"])
        return jres({"success": True})
    except Exception as e:
        return jres({"error": str(e)}, 400)

async def api_roles(req):
    t = req.rel_url.query.get("token", "")
    d = verify_token(t)
    if not d: return jres({"error": "unauthorized"}, 401)
    guild = bot.get_guild(d["guild_id"])
    if not guild: return jres({"error": "guild not found"}, 404)
    roles = [
        {"id": str(r.id), "name": r.name, "color": str(r.color), "position": r.position}
        for r in sorted(guild.roles, key=lambda r: -r.position)
        if r.name != "@everyone"
    ]
    return jres(roles)

async def api_members(req):
    t = req.rel_url.query.get("token", "")
    d = verify_token(t)
    if not d: return jres({"error": "unauthorized"}, 401)
    guild = bot.get_guild(d["guild_id"])
    if not guild: return jres({"error": "guild not found"}, 404)
    query = req.rel_url.query.get("q", "").lower().strip()
    members = []
    for m in guild.members:
        if m.bot:
            continue
        if query:
            # Search by ID, global name, display name (nickname)
            if not (
                query in str(m.id) or
                query in m.name.lower() or
                query in (m.display_name or "").lower() or
                query in (m.global_name or "").lower()
            ):
                continue
        members.append({
            "id":           str(m.id),
            "name":         m.name,
            "display_name": m.display_name,
            "global_name":  m.global_name or m.name,
            "avatar":       str(m.display_avatar.url),
        })
        if len(members) >= 25:
            break
    return jres(members)

# ══════════════════════════════════════════════════════════════════
#  ADVANCED MANAGE — ปิด permission ยศผู้ดูแล → ตรวจ audit → ลงโทษ → คืนยศ
# ══════════════════════════════════════════════════════════════════

# permission ที่ถือว่าเป็น "ยศผู้ดูแล"
ADV_LOCK_PERMS = [
    "administrator",
    "manage_guild",
    "manage_roles",
    "manage_channels",
    "ban_members",
    "kick_members",
    "manage_webhooks",
    "mention_everyone",
    "manage_messages",
    "manage_nicknames",
    "mute_members",
    "deafen_members",
    "move_members",
]

def _role_is_admin_like(role: discord.Role) -> bool:
    """คืน True ถ้า role มี permission ผู้ดูแลอย่างน้อย 1 ข้อ"""
    for perm in ADV_LOCK_PERMS:
        if getattr(role.permissions, perm, False):
            return True
    return False

async def do_advanced_lockdown(guild: discord.Guild, feature_key: str, cfg: dict,
                               known_offender_id: int | None = None):
    """
    โหมดตรวจจับขั้นสูง:
    1. จำ permissions เดิมของทุก role ที่เป็น admin-like
    2. ปิด permissions ทั้งหมดของ role เหล่านั้นทันที
    3. ใช้ known_offender_id (ที่รู้อยู่แล้ว) → ลงโทษทันที; fallback ดึง Audit Log
    4. ลงโทษคนผิดตาม feature_key
    5. คืน permissions ทุก role กลับเหมือนเดิม
    """
    guild_id = guild.id

    # ── ถ้า advanced lock กำลังทำงานอยู่ → ไม่รันซ้ำ ──
    if guild_id in bot.adv_lock_active:
        log.warning(f"[AdvLock] {guild.name}: already running, skip")
        return

    bot.adv_lock_active.add(guild_id)
    log.info(f"[AdvLock] {guild.name}: เริ่มโหมดจัดการขั้นสูง (feature={feature_key})")

    saved_perms: dict = {}  # role_id → discord.Permissions (ค่าเดิม)

    try:
        # ── STEP 1: หา role ที่ต้องปิด (ยกเว้น @everyone และ role ของบอทเอง) ──
        bot_member = guild.get_member(bot.user.id)
        bot_top    = bot_member.top_role.position if bot_member else 9999

        target_roles = []
        for role in guild.roles:
            if role.name == "@everyone":
                continue
            if role.position >= bot_top:
                # บอทไม่สามารถแก้ role ที่สูงกว่าตัวเองได้
                continue
            if _role_is_admin_like(role):
                target_roles.append(role)

        if not target_roles:
            log.info(f"[AdvLock] {guild.name}: ไม่พบ role ผู้ดูแลที่สามารถแก้ไขได้")
            bot.adv_lock_active.discard(guild_id)
            return

        # ── STEP 2: บันทึก permissions เดิม แล้วปิดทุกอย่าง ──
        log.info(f"[AdvLock] {guild.name}: ปิด permissions {len(target_roles)} role")
        tasks_disable = []
        for role in target_roles:
            saved_perms[role.id] = role.permissions  # จำไว้
            zero_perms = discord.Permissions.none()
            tasks_disable.append(role.edit(permissions=zero_perms, reason="[AdvLock] ปิดชั่วคราว — กำลังตรวจสอบ"))

        # ปิดทุก role พร้อมกัน (parallel)
        results = await asyncio.gather(*tasks_disable, return_exceptions=True)
        for i, res in enumerate(results):
            if isinstance(res, Exception):
                log.warning(f"[AdvLock] ปิด role {target_roles[i].name} ไม่ได้: {res}")

        # บันทึก state
        bot.adv_lock_state[guild_id] = saved_perms

        # แจ้ง log channel
        em_start = discord.Embed(
            title="🔴 จัดการขั้นสูง — เริ่มทำงาน",
            description=(
                f"ปิดสิทธิ์ผู้ดูแลทั้งหมด **{len(target_roles)} role** ชั่วคราว\n"
                f"กำลังตรวจสอบผู้กระทำ..."
            ),
            color=0xff4757,
        )
        em_start.set_footer(text=f"Feature: {feature_key} | Guild: {guild_id}")
        await send_log(guild, em_start)

        # ── STEP 3: ระบุผู้กระทำ ──
        offender_id     = known_offender_id  # ใช้ actor ที่รู้อยู่แล้วทันที
        offender_action = feature_key.replace("anti_", "")

        # fallback: ถ้าไม่มี known_offender_id → ดึง Audit Log
        if offender_id is None:
            await asyncio.sleep(2)
            try:
                feat = cfg.get(feature_key, {})
                window_sec = feat.get("window", 10)
                cutoff = datetime.now(timezone.utc) - timedelta(seconds=max(window_sec * 3, 60))

                ACTION_MAP = {
                    "anti_ch_delete":    discord.AuditLogAction.channel_delete,
                    "anti_ch_create":    discord.AuditLogAction.channel_create,
                    "anti_ch_update":    discord.AuditLogAction.channel_update,
                    "anti_ban":          discord.AuditLogAction.ban,
                    "anti_kick":         discord.AuditLogAction.kick,
                    "anti_role_create":  discord.AuditLogAction.role_create,
                    "anti_role_delete":  discord.AuditLogAction.role_delete,
                    "anti_role_update":  discord.AuditLogAction.role_update,
                    "anti_role_give":    discord.AuditLogAction.member_role_update,
                    "anti_webhook_create": discord.AuditLogAction.webhook_create,
                    "anti_webhook_delete": discord.AuditLogAction.webhook_delete,
                    "anti_guild_update": discord.AuditLogAction.guild_update,
                    "anti_prune":        discord.AuditLogAction.member_prune,
                }

                audit_action = ACTION_MAP.get(feature_key)
                user_counts: dict = {}

                async for entry in guild.audit_logs(limit=50, oldest_first=False):
                    if entry.created_at < cutoff:
                        break
                    if audit_action and entry.action != audit_action:
                        continue
                    uid = entry.user.id
                    if entry.user.bot:
                        continue
                    if uid == guild.owner_id:
                        continue
                    user_counts[uid] = user_counts.get(uid, 0) + 1
                    offender_action = str(entry.action).replace("AuditLogAction.", "")

                if user_counts:
                    offender_id = max(user_counts, key=user_counts.get)

            except Exception as e:
                log.error(f"[AdvLock] ดึง audit log ไม่ได้: {e}")

        # ── STEP 4: ลงโทษ ──
        if offender_id:
            try:
                offender = guild.get_member(offender_id)
                if offender is None:
                    offender = await guild.fetch_member(offender_id)
            except Exception:
                offender = None

            if offender and not is_whitelisted(offender, cfg):
                feat = cfg.get(feature_key, {})
                punishment = feat.get("punishment", "ban")
                reason = f"[AdvLock] จัดการขั้นสูง: {offender_action} เกินกำหนด"
                await apply_punishment(guild, offender, punishment, reason)
                em_punish = discord.Embed(
                    title="⚖️ จัดการขั้นสูง — ลงโทษแล้ว",
                    description=(
                        f"**ผู้กระทำ:** {offender.mention} (`{offender}`)\n"
                        f"**Action:** {offender_action}\n"
                        f"**บทลงโทษ:** {punishment.upper()}\n"
                        f"**เหตุผล:** {reason}"
                    ),
                    color=0xffa502,
                )
                await send_log(guild, em_punish)
            else:
                em_nf = discord.Embed(
                    title="⚠️ จัดการขั้นสูง — ไม่พบผู้กระทำ",
                    description="ไม่พบผู้กระทำที่ชัดเจนใน Audit Log หรือผู้กระทำอยู่ใน Whitelist",
                    color=0xffa502,
                )
                await send_log(guild, em_nf)
        else:
            em_nf = discord.Embed(
                title="⚠️ จัดการขั้นสูง — ไม่พบผู้กระทำ",
                description="ไม่พบผู้กระทำที่ตรงกับ action นี้ใน Audit Log",
                color=0xffa502,
            )
            await send_log(guild, em_nf)

    except Exception as e:
        log.error(f"[AdvLock] error: {e}")

    finally:
        # ── STEP 5: คืน permissions ทุก role เสมอ ──
        await asyncio.sleep(1)
        restore_tasks = []
        restore_done  = []
        for role in guild.roles:
            orig = saved_perms.get(role.id)
            if orig is not None:
                restore_tasks.append(role.edit(permissions=orig, reason="[AdvLock] คืนสิทธิ์หลังตรวจสอบ"))
                restore_done.append(role.name)

        if restore_tasks:
            results = await asyncio.gather(*restore_tasks, return_exceptions=True)
            for i, res in enumerate(results):
                if isinstance(res, Exception):
                    log.warning(f"[AdvLock] คืน role {restore_done[i]} ไม่ได้: {res}")

        # ล้าง state
        bot.adv_lock_state.pop(guild_id, None)
        bot.adv_lock_active.discard(guild_id)

        em_done = discord.Embed(
            title="✅ จัดการขั้นสูง — เสร็จสิ้น",
            description=f"คืนสิทธิ์ **{len(saved_perms)} role** กลับเหมือนเดิมแล้ว",
            color=0x00c896,
        )
        await send_log(guild, em_done)
        log.info(f"[AdvLock] {guild.name}: เสร็จสิ้น คืน {len(saved_perms)} role แล้ว")


async def api_advanced_manage(req):
    """
    POST /api/advanced-manage
    body: { "feature_key": "anti_ch_delete", "enabled": true/false }
    → เปิด/ปิดโหมดจัดการขั้นสูงสำหรับ feature นั้น
    เมื่อเปิด: check_feature จะเรียก do_advanced_lockdown แทนการลงโทษปกติ
    """
    t = req.rel_url.query.get("token", "")
    d = verify_token(t)
    if not d: return jres({"error": "unauthorized"}, 401)
    guild = bot.get_guild(d["guild_id"])
    if not guild: return jres({"error": "guild not found"}, 404)
    try:
        body = await req.json()
        feature_key = body.get("feature_key", "")
        enabled     = bool(body.get("enabled", True))
        cfg = get_cfg(guild.id)
        # บันทึกโหมดใน config
        adv_modes = cfg.setdefault("advanced_mode", {})
        adv_modes[feature_key] = enabled
        await save_guild_data(d["guild_id"])
        return jres({"success": True, "feature_key": feature_key, "enabled": enabled})
    except Exception as e:
        return jres({"error": str(e)}, 400)


async def api_lockdown(req):
    t = req.rel_url.query.get("token", "")
    d = verify_token(t)
    if not d: return jres({"error": "unauthorized"}, 401)
    guild = bot.get_guild(d["guild_id"])
    if not guild: return jres({"error": "guild not found"}, 404)
    try:
        body = await req.json()
        enable = bool(body.get("enable", True))
        asyncio.create_task(do_lockdown(guild, enable))
        cfg = get_cfg(guild.id)
        cfg["server_lockdown"]["enabled"] = enable
        await save_guild_data(guild.id)
        return jres({"success": True, "lockdown": enable})
    except Exception as e:
        return jres({"error": str(e)}, 400)

async def api_member_detail(req):
    """Return member profile + per-protection exemptions stored in config."""
    t = req.rel_url.query.get("token", "")
    d = verify_token(t)
    if not d: return jres({"error": "unauthorized"}, 401)
    guild = bot.get_guild(d["guild_id"])
    if not guild: return jres({"error": "guild not found"}, 404)
    member_id = req.rel_url.query.get("member_id", "")
    if not member_id: return jres({"error": "member_id required"}, 400)
    try:
        member = guild.get_member(int(member_id))
        if not member: return jres({"error": "member not found"}, 404)
        cfg = get_cfg(guild.id)
        exemptions = cfg.get("member_exemptions", {}).get(member_id, {})
        roles = [{"id": str(r.id), "name": r.name, "color": str(r.color)} for r in member.roles if r.name != "@everyone"]
        return jres({
            "id":           str(member.id),
            "name":         member.name,
            "display_name": member.display_name,
            "global_name":  member.global_name or member.name,
            "avatar":       str(member.display_avatar.url),
            "joined_at":    member.joined_at.isoformat() if member.joined_at else None,
            "created_at":   member.created_at.isoformat(),
            "is_owner":     member.id == guild.owner_id,
            "roles":        roles,
            "exemptions":   exemptions,
        })
    except Exception as e:
        return jres({"error": str(e)}, 500)

async def api_save_member_exemptions(req):
    """Save per-member exemption settings."""
    t = req.rel_url.query.get("token", "")
    d = verify_token(t)
    if not d: return jres({"error": "unauthorized"}, 401)
    try:
        body = await req.json()
        member_id = str(body.get("member_id", ""))
        exemptions = body.get("exemptions", {})
        cfg = get_cfg(d["guild_id"])
        if "member_exemptions" not in cfg:
            cfg["member_exemptions"] = {}
        cfg["member_exemptions"][member_id] = exemptions
        await save_guild_data(d["guild_id"])
        return jres({"success": True})
    except Exception as e:
        return jres({"error": str(e)}, 400)

async def api_role_channels(req):
    """Return all channels with visibility/send-message permission for a given role."""
    t = req.rel_url.query.get("token", "")
    d = verify_token(t)
    if not d: return jres({"error": "unauthorized"}, 401)
    guild = bot.get_guild(d["guild_id"])
    if not guild: return jres({"error": "guild not found"}, 404)
    role_id = req.rel_url.query.get("role_id", "")
    if not role_id: return jres({"error": "role_id required"}, 400)
    try:
        role = guild.get_role(int(role_id))
        if not role: return jres({"error": "role not found"}, 404)
        result = []
        for ch in sorted(guild.channels, key=lambda c: (str(type(c).__name__), c.position)):
            if not isinstance(ch, (discord.TextChannel, discord.VoiceChannel, discord.ForumChannel)):
                continue
            perms = ch.permissions_for(role)
            can_view = perms.view_channel
            can_send = perms.send_messages if isinstance(ch, discord.TextChannel) else perms.connect
            category = ch.category.name if ch.category else "—"
            result.append({
                "id":       str(ch.id),
                "name":     ch.name,
                "type":     type(ch).__name__,
                "category": category,
                "can_view": can_view,
                "can_send": can_send,
            })
        return jres(result)
    except Exception as e:
        return jres({"error": str(e)}, 500)

async def api_suspicious_alerts(req):
    """Return suspicious behavior alerts for the guild."""
    t = req.rel_url.query.get("token", "")
    d = verify_token(t)
    if not d: return jres({"error": "unauthorized"}, 401)
    guild = bot.get_guild(d["guild_id"])
    if not guild: return jres({"error": "guild not found"}, 404)
    alerts = list(reversed(bot.suspicious_alerts[d["guild_id"]]))
    # Enrich with member info
    result = []
    for a in alerts:
        member = guild.get_member(a["user_id"])
        result.append({
            **a,
            "user_id":      str(a["user_id"]),
            "ts":           a["ts"],
            "member_name":  member.display_name if member else f"Unknown ({a['user_id']})",
            "member_avatar": str(member.display_avatar.url) if member else "",
        })
    return jres(result)

async def api_mark_alert_read(req):
    """Mark a suspicious alert as read."""
    t = req.rel_url.query.get("token", "")
    d = verify_token(t)
    if not d: return jres({"error": "unauthorized"}, 401)
    try:
        body = await req.json()
        alert_id = body.get("id", "")
        for a in bot.suspicious_alerts[d["guild_id"]]:
            if a["id"] == alert_id:
                a["read"] = True
                break
        return jres({"success": True})
    except Exception as e:
        return jres({"error": str(e)}, 400)

async def api_member_actions(req):
    """Return action history for a specific member."""
    t = req.rel_url.query.get("token", "")
    d = verify_token(t)
    if not d: return jres({"error": "unauthorized"}, 401)
    member_id = req.rel_url.query.get("member_id", "")
    if not member_id: return jres({"error": "member_id required"}, 400)
    actions = list(reversed(bot.member_actions[d["guild_id"]].get(int(member_id), [])))
    return jres(actions[:100])  # last 100 actions

# ══════════════════════════════════════════════════════════════════
#  DASHBOARD HTML
# ══════════════════════════════════════════════════════════════════
DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="th">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=1.0,user-scalable=no"/>
<title>Security Bot Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=Kanit:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet"/>
<script src="https://cdnjs.cloudflare.com/ajax/libs/lucide/0.383.0/umd/lucide.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
:root{
  --bg:#07090f;--surface:#0d1117;--surface2:#111827;--surface3:#1a2234;
  --border:#1e2d45;--border2:#263552;--text:#c9d8f0;--muted:#3d5478;--muted2:#5a7ba0;
  --primary:#3b6ef8;--primary-light:#5585ff;--primary-glow:rgba(59,110,248,.2);
  --accent:#00d4ff;--success:#00c896;--success-dim:rgba(0,200,150,.12);
  --danger:#ff4757;--danger-dim:rgba(255,71,87,.12);
  --warn:#ffa502;--warn-dim:rgba(255,165,2,.12);
  --purple:#a855f7;--purple-dim:rgba(168,85,247,.12);
  --sidebar:240px;--nav-h:60px;--r:14px;--r-sm:9px;
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
html,body{height:100%;}
body{font-family:'Kanit',sans-serif;background:var(--bg);color:var(--text);min-height:100%;overflow-x:hidden;font-size:14px;line-height:1.55;}
::-webkit-scrollbar{width:4px;height:4px;}
::-webkit-scrollbar-track{background:transparent;}
::-webkit-scrollbar-thumb{background:var(--border2);border-radius:4px;}
.hidden{display:none!important;}
.mono{font-family:'JetBrains Mono',monospace;}

/* ANIMATIONS */
@keyframes fadeUp{from{opacity:0;transform:translateY(18px)}to{opacity:1;transform:translateY(0)}}
@keyframes spin{to{transform:rotate(360deg)}}
@keyframes glow{0%,100%{box-shadow:0 0 20px rgba(59,110,248,.3)}50%{box-shadow:0 0 40px rgba(59,110,248,.6)}}
@keyframes toastIn{from{opacity:0;transform:translateX(110%)}to{opacity:1;transform:translateX(0)}}
@keyframes toastOut{from{opacity:1}to{opacity:0;transform:translateX(110%)}}
@keyframes shimmer{0%{background-position:-600px 0}100%{background-position:600px 0}}

/* LOGIN */
#login-view{position:fixed;inset:0;z-index:1000;display:flex;align-items:center;justify-content:center;
  background:radial-gradient(ellipse 80% 50% at 30% 20%,rgba(59,110,248,.12),transparent),
  radial-gradient(ellipse 50% 60% at 80% 80%,rgba(0,212,255,.07),transparent),var(--bg);
  background-size:auto,auto,auto;
}
.login-card{width:100%;max-width:400px;margin:20px;background:var(--surface);border:1px solid var(--border);
  border-radius:20px;padding:40px 36px;display:flex;flex-direction:column;gap:22px;
  animation:fadeUp .6s cubic-bezier(.16,1,.3,1) both;box-shadow:0 40px 80px rgba(0,0,0,.65),0 0 0 1px rgba(59,110,248,.1),inset 0 1px 0 rgba(255,255,255,.04);}
.login-logo{display:flex;flex-direction:column;align-items:center;gap:14px;text-align:center;}
.logo-ring{width:72px;height:72px;background:linear-gradient(135deg,var(--primary) 0%,var(--accent) 100%);
  border-radius:20px;display:flex;align-items:center;justify-content:center;animation:glow 3s ease-in-out infinite;box-shadow:0 8px 24px rgba(59,110,248,.45);}
.login-title{font-size:26px;font-weight:800;color:#fff;letter-spacing:-.5px;}
.login-sub{font-size:13px;color:var(--muted2);}
.fl{display:flex;flex-direction:column;gap:8px;}
.fl label{font-size:11px;font-weight:600;color:var(--muted2);text-transform:uppercase;letter-spacing:.7px;}
.fi{background:var(--surface2);border:1.5px solid var(--border2);border-radius:var(--r-sm);padding:13px 14px;
  color:var(--text);font-size:14px;font-family:'Kanit',sans-serif;outline:none;width:100%;min-height:48px;transition:border-color .2s,box-shadow .2s;}
.fi:focus{border-color:var(--primary-light);box-shadow:0 0 0 3px var(--primary-glow);}
.fi::placeholder{color:var(--muted);}
.btn-login{background:linear-gradient(135deg,var(--primary),var(--primary-light));color:#fff;border:none;
  border-radius:var(--r-sm);padding:14px;font-size:14px;font-weight:700;font-family:'Kanit',sans-serif;
  cursor:pointer;width:100%;min-height:48px;box-shadow:0 4px 20px rgba(59,110,248,.4);transition:transform .15s,box-shadow .15s;
  display:flex;align-items:center;justify-content:center;gap:8px;letter-spacing:.3px;}
.btn-login:hover{transform:translateY(-1px);box-shadow:0 8px 28px rgba(59,110,248,.6);}
.login-hint{text-align:center;font-size:12px;color:var(--muted);}
.login-hint code{background:var(--surface2);padding:2px 7px;border-radius:5px;color:var(--accent);font-family:'JetBrains Mono',monospace;font-size:11px;}
.login-err{display:none;background:var(--danger-dim);border:1px solid rgba(255,71,87,.3);color:#ffa0aa;border-radius:var(--r-sm);padding:10px 14px;font-size:13px;}
.login-err.show{display:block;}

/* APP */
#app-view{display:none;min-height:100vh;}
#app-view.active{display:flex;}

/* SIDEBAR */
#sidebar{width:var(--sidebar);min-height:100vh;background:linear-gradient(180deg,#0c1220 0%,#070c18 100%);
  border-right:1px solid var(--border);position:fixed;left:0;top:0;bottom:0;z-index:100;display:flex;flex-direction:column;overflow:hidden;}
.sb-head{padding:22px 16px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:12px;}
.sb-icon{width:40px;height:40px;border-radius:12px;flex-shrink:0;background:linear-gradient(135deg,var(--primary),var(--accent));
  display:flex;align-items:center;justify-content:center;box-shadow:0 4px 14px rgba(59,110,248,.4);}
.sb-title{font-size:14px;font-weight:700;color:#fff;letter-spacing:.3px;}
.sb-sub{font-size:10px;color:var(--muted);margin-top:1px;letter-spacing:.4px;}
.sb-server{margin:10px 10px 4px;padding:11px 12px;background:var(--surface2);border:1px solid var(--border);border-radius:10px;display:flex;align-items:center;gap:9px;transition:border-color .15s;}
.sb-server:hover{border-color:var(--border2);}
.sb-sicon{width:34px;height:34px;border-radius:8px;flex-shrink:0;background:var(--primary-glow);overflow:hidden;display:flex;align-items:center;justify-content:center;color:var(--primary-light);}
.sb-sicon img{width:100%;height:100%;object-fit:cover;border-radius:8px;}
.sb-sname{font-size:12px;font-weight:600;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.sb-sid{font-size:10px;color:var(--muted);font-family:'JetBrains Mono',monospace;}
.sb-nav{flex:1;overflow-y:auto;padding:6px 8px;display:flex;flex-direction:column;gap:1px;}
.sb-nav::-webkit-scrollbar{width:0;}
.sb-section{font-size:9.5px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:1.1px;padding:14px 8px 3px;display:flex;align-items:center;gap:5px;}
.nav-item{display:flex;align-items:center;gap:9px;padding:8px 10px;border-radius:8px;cursor:pointer;color:var(--muted2);
  font-size:12.5px;font-weight:400;transition:all .14s;border:1px solid transparent;user-select:none;}
.nav-item:hover{background:var(--surface2);color:var(--text);}
.nav-item.active{background:linear-gradient(90deg,rgba(59,110,248,.18),rgba(59,110,248,.05));color:var(--primary-light);border-color:rgba(91,133,255,.2);font-weight:500;}
.nav-item.active .nav-ic svg{stroke:var(--primary-light);}
.nav-dot{width:6px;height:6px;border-radius:50%;background:var(--success);flex-shrink:0;display:none;box-shadow:0 0 6px var(--success);}
.nav-item.active .nav-dot{display:block;}
.nav-ic{width:20px;flex-shrink:0;display:flex;align-items:center;justify-content:center;}
.nav-ic svg{width:14px;height:14px;stroke-width:1.8;transition:stroke .14s;}
.sb-foot{padding:10px;border-top:1px solid var(--border);}
.sb-logout{display:flex;align-items:center;gap:8px;padding:9px 10px;border-radius:8px;cursor:pointer;color:var(--muted2);font-size:12.5px;transition:all .15s;}
.sb-logout:hover{background:var(--danger-dim);color:var(--danger);}

/* MAIN */
#main{margin-left:var(--sidebar);flex:1;min-height:100vh;display:flex;flex-direction:column;}
.main-head{padding:22px 28px 0;display:flex;align-items:center;justify-content:space-between;gap:16px;}
.page-title{font-size:20px;font-weight:800;color:#fff;letter-spacing:-.3px;}
.page-sub{font-size:12px;color:var(--muted);margin-top:3px;}
.main-body{padding:20px 24px 56px;}
.page{display:none;}
.page.active{display:block;animation:fadeUp .35s cubic-bezier(.16,1,.3,1) both;}

/* CARD */
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);padding:20px;margin-bottom:14px;transition:border-color .15s;}
.card-title{font-size:10.5px;font-weight:700;color:var(--muted2);text-transform:uppercase;letter-spacing:.9px;margin-bottom:16px;display:flex;align-items:center;gap:7px;}

/* STATS */
.stats-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px;}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);padding:18px 16px 14px;position:relative;overflow:hidden;animation:fadeUp .4s cubic-bezier(.16,1,.3,1) both;transition:border-color .15s,transform .15s,box-shadow .15s;}
.stat-card:hover{border-color:var(--border2);transform:translateY(-2px);box-shadow:0 6px 24px rgba(0,0,0,.25);}
.stat-ic{position:absolute;top:12px;right:12px;font-size:22px;opacity:1;display:flex;align-items:center;justify-content:center;}
.stat-num{font-size:30px;font-weight:800;color:#fff;letter-spacing:-1.5px;line-height:1;margin-top:6px;}
.stat-label{font-size:11px;color:var(--muted2);margin-top:5px;letter-spacing:.3px;}

/* BANNER */
#server-banner{height:140px;border-radius:var(--r);margin-bottom:14px;position:relative;overflow:hidden;border:1px solid var(--border);background:linear-gradient(135deg,#0a1628,#07121f);}
.banner-bg{position:absolute;inset:0;background:linear-gradient(135deg,rgba(59,110,248,.3),rgba(0,212,255,.12));}
.banner-content{position:relative;z-index:1;padding:18px;display:flex;align-items:flex-end;height:100%;}
.banner-icon{width:60px;height:60px;border-radius:14px;border:2px solid rgba(255,255,255,.15);background:var(--primary);display:flex;align-items:center;justify-content:center;font-size:22px;font-weight:800;color:#fff;overflow:hidden;flex-shrink:0;}
.banner-icon img{width:100%;height:100%;object-fit:cover;}
.banner-info{margin-left:14px;}
.banner-name{font-size:20px;font-weight:800;color:#fff;letter-spacing:-.4px;text-shadow:0 2px 8px rgba(0,0,0,.4);}
.banner-members{font-size:12px;color:rgba(255,255,255,.6);margin-top:2px;}

/* FEATURE GRID — 1 feature = 1 card */
.feature-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:14px;margin-bottom:14px;}
.feat-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);overflow:hidden;transition:border-color .15s,box-shadow .15s,transform .15s;animation:fadeUp .4s cubic-bezier(.16,1,.3,1) both;}
.feat-card:hover{border-color:var(--border2);transform:translateY(-1px);box-shadow:0 4px 16px rgba(0,0,0,.2);}
.feat-card.enabled{border-color:rgba(59,110,248,.45);box-shadow:0 0 0 1px rgba(59,110,248,.15),0 4px 20px rgba(59,110,248,.08);}
.feat-header{display:flex;align-items:center;gap:12px;padding:14px 16px;border-bottom:1px solid var(--border);background:linear-gradient(90deg,var(--surface2),var(--surface));}
.feat-emoji{font-size:20px;width:28px;height:28px;display:flex;align-items:center;justify-content:center;flex-shrink:0;color:var(--muted2);}
.feat-emoji svg{width:16px;height:16px;stroke-width:1.8;}
.feat-label{flex:1;}
.feat-name{font-size:14px;font-weight:700;color:#fff;}
.feat-desc{font-size:11px;color:var(--muted);margin-top:1px;}
.feat-body{padding:14px 16px;display:flex;flex-direction:column;gap:11px;}

/* TOGGLE */
.tog{position:relative;display:inline-block;width:48px;height:26px;flex-shrink:0;}
.tog input{opacity:0;width:0;height:0;}
.tog-sl{position:absolute;cursor:pointer;inset:0;background:var(--border2);border-radius:26px;transition:background .2s;}
.tog-sl::before{content:'';position:absolute;width:20px;height:20px;left:3px;top:3px;background:#fff;border-radius:50%;transition:transform .2s cubic-bezier(.16,1,.3,1);box-shadow:0 1px 4px rgba(0,0,0,.4);}
.tog input:checked+.tog-sl{background:var(--success);}
.tog input:checked+.tog-sl::before{transform:translateX(22px);}

/* FIELD */
.sub-field{display:flex;flex-direction:column;gap:5px;}
.sub-label{font-size:10px;font-weight:700;color:var(--muted2);text-transform:uppercase;letter-spacing:.6px;}
.sub-row{display:flex;gap:8px;align-items:center;}
.sub-input{background:var(--surface2);border:1.5px solid var(--border2);border-radius:var(--r-sm);padding:7px 10px;
  color:var(--text);font-size:13px;font-family:'Kanit',sans-serif;outline:none;flex:1;min-height:36px;transition:border-color .2s;}
.sub-input:focus{border-color:var(--primary-light);}
.sub-unit{font-size:11px;color:var(--muted);white-space:nowrap;}

/* PUNISHMENT SELECTOR */
.punish-wrap{display:grid;grid-template-columns:repeat(3,1fr);gap:5px;}
.punish-btn{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:2px;padding:7px 3px;
  border-radius:7px;border:1.5px solid var(--border);background:var(--surface2);cursor:pointer;
  transition:all .15s;color:var(--muted2);font-size:10px;font-weight:600;font-family:'Kanit',sans-serif;}
.punish-btn:hover{border-color:var(--border2);color:var(--text);}
.punish-btn.sel{border-color:var(--primary-light);background:var(--primary-glow);color:var(--primary-light);}
.punish-btn.sel.p-ban{border-color:var(--danger);background:var(--danger-dim);color:var(--danger);}
.punish-btn.sel.p-kick{border-color:var(--warn);background:var(--warn-dim);color:var(--warn);}
.punish-btn.sel.p-timeout{border-color:var(--accent);background:rgba(0,212,255,.1);color:var(--accent);}
.punish-btn.sel.p-quarantine{border-color:var(--purple);background:var(--purple-dim);color:var(--purple);}
.punish-btn.sel.p-log{border-color:var(--muted2);background:rgba(90,123,160,.1);color:var(--muted2);}
.punish-ic{font-size:14px;line-height:1;display:flex;align-items:center;justify-content:center;width:18px;height:18px;}

.adv-toggle-row{display:flex;align-items:center;gap:14px;padding:13px 16px;
  background:linear-gradient(90deg,rgba(168,85,247,.08),rgba(255,71,87,.05));
  border-top:1px solid rgba(168,85,247,.2);border-radius:0 0 var(--r) var(--r);
  transition:background .2s;}
.adv-toggle-row:has(input:checked){background:linear-gradient(90deg,rgba(168,85,247,.18),rgba(255,71,87,.10));border-top-color:rgba(168,85,247,.4);}
.adv-toggle-ic{width:26px;height:26px;flex-shrink:0;display:flex;align-items:center;justify-content:center;
  background:rgba(168,85,247,.15);border-radius:7px;color:#c084fc;}
.adv-toggle-info{flex:1;}
.adv-toggle-label{font-size:13px;font-weight:700;color:#c084fc;}
.adv-toggle-desc{font-size:11px;color:var(--muted);margin-top:2px;}

/* BUTTONS */
.btn{display:inline-flex;align-items:center;gap:6px;padding:9px 16px;border-radius:var(--r-sm);border:1px solid var(--border2);
  background:var(--surface2);color:var(--text);font-size:13px;font-weight:600;font-family:'Kanit',sans-serif;cursor:pointer;transition:all .15s;white-space:nowrap;min-height:40px;}
.btn:hover{background:var(--surface3);border-color:var(--border2);}
.btn-primary{background:var(--primary);border-color:var(--primary);color:#fff;box-shadow:0 2px 12px rgba(59,110,248,.3);}
.btn-primary:hover{background:var(--primary-light);}
.btn-success{background:var(--success-dim);border-color:rgba(0,200,150,.3);color:var(--success);}
.btn-danger{background:var(--danger-dim);border-color:rgba(255,71,87,.3);color:var(--danger);}
.btn-sm{padding:6px 12px;font-size:12px;min-height:32px;}
.btn-full{width:100%;justify-content:center;}
.btn:disabled{opacity:.45;cursor:not-allowed;}

/* INPUT */
.input{background:var(--surface2);border:1.5px solid var(--border2);border-radius:var(--r-sm);padding:10px 12px;
  color:var(--text);font-size:14px;font-family:'Kanit',sans-serif;outline:none;width:100%;min-height:44px;transition:border-color .2s,box-shadow .2s;}
.input:focus{border-color:var(--primary-light);box-shadow:0 0 0 3px var(--primary-glow);}
.input::placeholder{color:var(--muted);}
textarea.input{min-height:80px;resize:vertical;}
select.input{cursor:pointer;appearance:none;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='8'%3E%3Cpath d='M6 8L0 0h12z' fill='%235a7ba0'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 12px center;}
.field-group{margin-bottom:14px;}
.field-group:last-child{margin-bottom:0;}
.fl-label{font-size:11px;font-weight:600;color:var(--muted2);text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px;display:block;}
.chips-wrap{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px;min-height:32px;}
.chip{display:inline-flex;align-items:center;gap:5px;background:var(--surface2);border:1px solid var(--border2);border-radius:20px;padding:4px 10px 4px 12px;font-size:12px;color:var(--text);}
.chip button{background:none;border:none;color:var(--muted);cursor:pointer;font-size:14px;padding:0;transition:color .15s;}
.chip button:hover{color:var(--danger);}

/* TOGGLE ROW */
.trow{display:flex;align-items:center;gap:14px;padding:13px 0;border-bottom:1px solid var(--border);}
.trow:last-child{border-bottom:none;padding-bottom:0;}
.trow:first-child{padding-top:0;}
.trow-ic{font-size:17px;width:26px;height:26px;text-align:center;flex-shrink:0;display:flex;align-items:center;justify-content:center;}
.trow-ic svg{width:15px;height:15px;stroke:var(--muted2);}
.trow-info{flex:1;}
.trow-label{font-size:13px;font-weight:600;color:var(--text);}
.trow-desc{font-size:11px;color:var(--muted);margin-top:2px;}
.badge{padding:2px 8px;border-radius:20px;font-size:10px;font-weight:700;}
.badge-green{background:var(--success-dim);color:var(--success);}
.badge-red{background:var(--danger-dim);color:var(--danger);}
.badge-gray{background:rgba(61,84,120,.2);color:var(--muted2);}

/* LOG CHANNELS */
.logch-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:10px;}
.logch-card{background:var(--surface2);border:1px solid var(--border);border-radius:var(--r-sm);padding:13px 15px;
  display:flex;align-items:center;justify-content:space-between;gap:12px;transition:border-color .2s;}
.logch-card:hover{border-color:var(--border2);}
.logch-left{display:flex;align-items:center;gap:11px;}
.logch-ic{font-size:18px;width:26px;text-align:center;}
.logch-name{font-size:13px;font-weight:600;color:var(--text);}
.logch-st{font-size:11px;margin-top:2px;}
.logch-st.has{color:var(--success);}
.logch-st.none{color:var(--muted);}
.sus-dot{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:5px;vertical-align:middle;}
.logch-ic{width:28px;height:28px;display:flex;align-items:center;justify-content:center;background:var(--surface3);border-radius:7px;color:var(--muted2);flex-shrink:0;}

/* LOGS */
.log-list{display:flex;flex-direction:column;gap:2px;}
.log-item{display:flex;align-items:center;gap:12px;padding:9px 13px;border-radius:8px;transition:background .15s;}
.log-item:hover{background:var(--surface2);}
.log-badge{padding:3px 9px;border-radius:20px;font-size:11px;font-weight:600;white-space:nowrap;flex-shrink:0;}
.log-body{flex:1;min-width:0;}
.log-action{font-size:13px;font-weight:600;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.log-meta{font-size:11px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.log-time{font-size:11px;color:var(--muted);flex-shrink:0;font-family:'JetBrains Mono',monospace;}

/* SEC HEAD */
.sec-head{font-size:15px;font-weight:700;color:#fff;margin:22px 0 12px;display:flex;align-items:center;gap:8px;}
.sec-head:first-child{margin-top:0;}

/* TOAST */
#toast-wrap{position:fixed;top:18px;right:18px;z-index:9999;display:flex;flex-direction:column;gap:8px;pointer-events:none;}
.toast{background:rgba(17,24,39,.95);border:1px solid var(--border2);border-radius:10px;padding:12px 18px;font-size:12.5px;color:var(--text);backdrop-filter:blur(12px);
  box-shadow:0 8px 28px rgba(0,0,0,.5);animation:toastIn .3s cubic-bezier(.16,1,.3,1) both;max-width:280px;pointer-events:auto;display:flex;align-items:center;gap:8px;}
.toast.success{border-left:3px solid var(--success);background:rgba(0,30,20,.9);}
.toast.error{border-left:3px solid var(--danger);background:rgba(30,8,10,.9);}
.toast.fade-out{animation:toastOut .3s ease both;}

.loader{display:inline-block;width:18px;height:18px;border:2px solid var(--border2);border-top-color:var(--primary-light);border-radius:50%;animation:spin .7s linear infinite;}
.skeleton{background:linear-gradient(90deg,var(--surface) 25%,var(--surface2) 50%,var(--surface) 75%);background-size:600px 100%;animation:shimmer 1.5s infinite;border-radius:6px;color:transparent!important;pointer-events:none;}

/* LOCKDOWN BANNER */
.lockdown-banner{background:linear-gradient(90deg,var(--danger-dim),rgba(255,71,87,.05));border:1px solid rgba(255,71,87,.3);
  border-radius:var(--r);padding:14px 18px;margin-bottom:14px;display:flex;align-items:center;gap:14px;}
.lockdown-banner.hidden{display:none;}
.ld-icon{font-size:28px;}
.ld-info{flex:1;}
.ld-title{font-size:14px;font-weight:700;color:var(--danger);}
.ld-sub{font-size:12px;color:var(--muted2);margin-top:2px;}

/* CATEGORY CARDS */
.cat-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);padding:14px 16px;cursor:pointer;transition:all .18s;display:flex;flex-direction:column;gap:8px;}
.cat-card:hover{border-color:var(--border2);transform:translateY(-2px);box-shadow:0 4px 16px rgba(0,0,0,.3);}
.cat-card-head{display:flex;align-items:center;gap:10px;}
.cat-card-ic{font-size:22px;width:36px;height:36px;display:flex;align-items:center;justify-content:center;border-radius:10px;flex-shrink:0;}
.cat-card-ic svg{width:18px;height:18px;}
.cat-card-ic.nuke{background:rgba(255,71,87,.12);}
.cat-card-ic.raid{background:rgba(255,165,2,.12);}
.cat-card-ic.spam{background:rgba(59,110,248,.12);}
.cat-card-ic.general{background:rgba(0,200,150,.12);}
.cat-card-name{font-size:13px;font-weight:700;color:#fff;}
.cat-card-desc{font-size:11px;color:var(--muted);}
.cat-card-bar{height:3px;border-radius:2px;background:var(--border2);overflow:hidden;}
.cat-card-bar-fill{height:100%;border-radius:2px;transition:width .5s ease;}
.cat-card-bar-fill.nuke{background:var(--danger);}
.cat-card-bar-fill.raid{background:var(--warn);}
.cat-card-bar-fill.spam{background:var(--primary-light);}
.cat-card-bar-fill.general{background:var(--success);}
.cat-card-footer{display:flex;align-items:center;justify-content:space-between;font-size:11px;color:var(--muted);}
.cat-active-count{font-size:12px;font-weight:700;}
.cat-active-count.nuke{color:var(--danger);}
.cat-active-count.raid{color:var(--warn);}
.cat-active-count.spam{color:var(--primary-light);}
.cat-active-count.general{color:var(--success);}

/* BOTTOM NAV (mobile) */
#bottom-nav{display:none;position:fixed;bottom:0;left:0;right:0;height:var(--nav-h);z-index:200;
  background:var(--surface);border-top:1px solid var(--border);padding:0 4px;}

/* ROLE INSPECTOR */
.ri-role-item{display:flex;align-items:center;gap:10px;padding:10px 14px;background:var(--surface2);
  border:1px solid var(--border);border-radius:var(--r-sm);cursor:pointer;transition:all .15s;}
.ri-role-item:hover{border-color:var(--border2);transform:translateX(2px);}
.ri-role-dot{width:12px;height:12px;border-radius:50%;flex-shrink:0;}
.ri-role-name{flex:1;font-size:13px;font-weight:600;color:var(--text);}
.ri-role-arrow{color:var(--muted);font-size:12px;}

.ri-ch-row{display:flex;align-items:center;gap:10px;padding:8px 10px;border-radius:8px;transition:background .12s;}
.ri-ch-row:hover{background:var(--surface2);}
.ri-ch-icon{font-size:13px;width:20px;text-align:center;flex-shrink:0;}
.ri-ch-name{flex:1;font-size:13px;color:var(--text);}
.ri-ch-cat{font-size:10px;color:var(--muted);}
.ri-ch-badges{display:flex;gap:4px;flex-shrink:0;}
.ri-badge-ok{background:rgba(0,200,150,.12);color:var(--success);border:1px solid rgba(0,200,150,.25);
  border-radius:5px;padding:2px 7px;font-size:10px;font-weight:700;}
.ri-badge-no{background:var(--danger-dim);color:var(--danger);border:1px solid rgba(255,71,87,.25);
  border-radius:5px;padding:2px 7px;font-size:10px;font-weight:700;}
.bnav-inner{display:flex;align-items:stretch;height:100%;}
.bnav-item{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:3px;cursor:pointer;
  color:var(--muted2);font-size:10px;font-weight:500;transition:color .15s;border-radius:8px;margin:4px 2px;user-select:none;}
.bnav-item:hover,.bnav-item.active{color:var(--primary-light);}
.bnav-ic{font-size:17px;width:30px;height:26px;display:flex;align-items:center;justify-content:center;border-radius:7px;transition:background .15s;}
.bnav-ic svg{width:17px;height:17px;stroke-width:1.8;}
.bnav-item.active .bnav-ic{background:var(--primary-glow);}

@media(max-width:768px){
  #sidebar{display:none;}
  #main{margin-left:0;padding-bottom:var(--nav-h);}
  #bottom-nav{display:flex;}
  .main-head{padding:14px 14px 0;}
  .main-body{padding:14px 14px 24px;}
  .stats-grid{grid-template-columns:repeat(2,1fr);}
  .feature-grid{grid-template-columns:1fr;}
  .logch-grid{grid-template-columns:1fr;}
  #category-cards{grid-template-columns:1fr!important;}
}
</style>
</head>
<body>
<div id="toast-wrap"></div>

<!-- LOGIN -->
<div id="login-view">
  <div class="login-card">
    <div class="login-logo">
      <div class="logo-ring"><svg xmlns="http://www.w3.org/2000/svg" width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></div>
      <div>
        <div class="login-title">Security Bot</div>
        <div class="login-sub">กรอกรหัสที่ได้รับจาก DM เพื่อเข้าระบบ</div>
      </div>
    </div>
    <div class="fl">
      <label>รหัสเข้าสู่ระบบ (Token)</label>
      <input class="fi" type="password" id="token-inp" placeholder="วางรหัสที่นี่..." autocomplete="off"/>
    </div>
    <div class="login-err" id="login-err">รหัสไม่ถูกต้องหรือหมดอายุ</div>
    <button class="btn-login" onclick="doLogin()"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" y1="12" x2="3" y2="12"/></svg> เข้าสู่ระบบ</button>
    <div class="login-hint">ใช้คำสั่ง <code>/getcode</code> ใน Discord เพื่อรับรหัส</div>
  </div>
</div>

<!-- APP -->
<div id="app-view">
  <nav id="sidebar">
    <div class="sb-head">
      <div class="sb-icon"><svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></div>
      <div><div class="sb-title">Security Bot</div><div class="sb-sub">v2.0 Full</div></div>
    </div>
    <div class="sb-server">
      <div class="sb-sicon" id="sb-icon-wrap"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect width="20" height="8" x="2" y="2" rx="2" ry="2"/><rect width="20" height="8" x="2" y="14" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg></div>
      <div style="min-width:0;">
        <div class="sb-sname" id="sb-sname">กำลังโหลด...</div>
        <div class="sb-sid" id="sb-sid">—</div>
      </div>
    </div>
    <div class="sb-nav">
      <div class="sb-section">ภาพรวม</div>
      <div class="nav-item active" onclick="goPage('home')"><div class="nav-dot"></div><span class="nav-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect width="7" height="9" x="3" y="3" rx="1"/><rect width="7" height="5" x="14" y="3" rx="1"/><rect width="7" height="9" x="14" y="12" rx="1"/><rect width="7" height="5" x="3" y="16" rx="1"/></svg></span>หน้าหลัก</div>
      <div class="nav-item" onclick="goPage('logs')"><span class="nav-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M8 21h12a2 2 0 0 0 2-2v-2H10v2a2 2 0 1 1-4 0V5a2 2 0 1 0-4 0v3h4"/><path d="M19 3H5"/><path d="M14 15H8"/><path d="M14 11H8"/></svg></span>ประวัติ Audit</div>
      <div class="sb-section"><span style="color:var(--danger);opacity:.7;">—</span> Anti-Nuke</div>
      <div class="nav-item" onclick="goPage('antinuke')"><span class="nav-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg></span>Anti-Nuke</div>
      <div class="sb-section"><span style="color:var(--warn);opacity:.7;">—</span> Anti-Raid</div>
      <div class="nav-item" onclick="goPage('antiraid')"><span class="nav-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M11 3a1 1 0 1 0 2 0 1 1 0 0 0-2 0"/><path d="M11 21a1 1 0 1 0 2 0 1 1 0 0 0-2 0"/><path d="M3 11a1 1 0 1 0 0 2 1 1 0 0 0 0-2"/><path d="M21 11a1 1 0 1 0 0 2 1 1 0 0 0 0-2"/><path d="m15.5 4.5-2 4.5H11l-2 4.5"/><path d="M12 12a1 1 0 1 0 2 0 1 1 0 0 0-2 0"/><circle cx="12" cy="12" r="9"/></svg></span>Anti-Raid & Gatekeeper</div>
      <div class="nav-item" onclick="goPage('lockdown')"><span class="nav-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg></span>Server Lockdown</div>
      <div class="sb-section"><span style="color:var(--primary-light);opacity:.7;">—</span> Anti-Spam</div>
      <div class="nav-item" onclick="goPage('antispam')"><span class="nav-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/><line x1="9" y1="10" x2="9" y2="10"/><line x1="12" y1="10" x2="12" y2="10"/><line x1="15" y1="10" x2="15" y2="10"/></svg></span>Anti-Spam & Content</div>
      <div class="sb-section"><span style="color:var(--success);opacity:.7;">—</span> ทั่วไป</div>
      <div class="nav-item" onclick="goPage('automod')"><span class="nav-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 8V4H8"/><rect width="16" height="12" x="4" y="8" rx="2"/><path d="M2 14h2"/><path d="M20 14h2"/><path d="M15 13v2"/><path d="M9 13v2"/></svg></span>Auto Mod</div>
      <div class="nav-item" onclick="goPage('voiceabuse')"><span class="nav-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2a3 3 0 0 0-3 3v7a3 3 0 0 0 6 0V5a3 3 0 0 0-3-3Z"/><path d="M19 10v2a7 7 0 0 1-14 0v-2"/><line x1="12" y1="19" x2="12" y2="22"/></svg></span>Voice Abuse</div>
      <div class="nav-item" onclick="goPage('welcome')"><span class="nav-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M13 4h3a2 2 0 0 1 2 2v14"/><path d="M2 20h3"/><path d="M13 20h9"/><path d="M10 12v.01"/><path d="M13 4.562v16.157a1 1 0 0 1-1.242.97L5 20V5.562a2 2 0 0 1 1.515-1.94l4-1A2 2 0 0 1 13 4.561Z"/></svg></span>Welcome</div>
      <div class="nav-item" onclick="goPage('whitelist')"><span class="nav-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg></span>Whitelist</div>
      <div class="nav-item" onclick="goPage('memberprofile')"><span class="nav-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="10" cy="8" r="4"/><path d="M10.3 15H7a4 4 0 0 0-4 4v1"/><circle cx="17" cy="16" r="3"/><path d="m21 20-1.9-1.9"/></svg></span>โปรไฟล์สมาชิก</div>
      <div class="nav-item" onclick="goPage('suspicious')"><span class="nav-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M5.5 8.5 9 12l-3.5 3.5L2 12l3.5-3.5Z"/><path d="m12 2 3.5 3.5L12 9 8.5 5.5 12 2Z"/><path d="M18.5 8.5 22 12l-3.5 3.5L15 12l3.5-3.5Z"/><path d="m12 15 3.5 3.5L12 22l-3.5-3.5L12 15Z"/></svg></span>พฤติกรรมน่าสงสัย</div>
      <div class="nav-item" onclick="goPage('roleinspector')"><span class="nav-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2H2v10l9.29 9.29c.94.94 2.48.94 3.42 0l6.58-6.58c.94-.94.94-2.48 0-3.42L12 2Z"/><path d="M7 7h.01"/></svg></span>Role Inspector</div>
      <div class="nav-item" onclick="goPage('logchannels')"><span class="nav-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="m3 11 19-9-9 19-2-8-8-2z"/></svg></span>Log Channels</div>
      <div class="nav-item" onclick="goPage('settings')"><span class="nav-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/><circle cx="12" cy="12" r="3"/></svg></span>ตั้งค่าทั่วไป</div>
    </div>
    <div class="sb-foot">
      <div class="sb-logout" onclick="doLogout()"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg> ออกจากระบบ</div>
    </div>
  </nav>

  <div id="main">
    <div class="main-head">
      <div>
        <div class="page-title" id="page-title">หน้าหลัก</div>
        <div class="page-sub" id="page-sub">ภาพรวมของ Server</div>
      </div>
      <button class="btn btn-primary btn-sm" onclick="saveConfig()"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right:4px;"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg> บันทึก</button>
    </div>
    <div class="main-body">

      <!-- ═══ HOME ═══ -->
      <div class="page active" id="page-home">
        <div class="lockdown-banner hidden" id="ld-banner">
          <div class="ld-icon"><svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="var(--danger)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg></div>
          <div class="ld-info">
            <div class="ld-title">Server Lockdown เปิดอยู่</div>
            <div class="ld-sub">ทุกห้องถูกล็อก — ลิงก์เชิญถูกยกเลิกทั้งหมด</div>
          </div>
          <button class="btn btn-danger btn-sm" onclick="toggleLockdown(false)"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/></svg> ปลดล็อก</button>
        </div>
        <div id="server-banner">
          <div class="banner-bg"></div>
          <div class="banner-content">
            <div class="banner-icon" id="ban-icon"><svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="rgba(255,255,255,.6)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect width="20" height="8" x="2" y="2" rx="2" ry="2"/><rect width="20" height="8" x="2" y="14" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg></div>
            <div class="banner-info">
              <div class="banner-name" id="ban-name"><span class="skeleton" style="width:160px;height:22px;display:inline-block;"></span></div>
              <div class="banner-members" id="ban-members"></div>
            </div>
          </div>
        </div>
        <div class="stats-grid" id="stats-grid">
          <div class="stat-card"><div class="stat-ic"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="var(--primary-light)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg></div><div class="stat-num skeleton" id="st-members">—</div><div class="stat-label">สมาชิกทั้งหมด</div></div>
          <div class="stat-card"><div class="stat-ic"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="var(--success)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><line x1="12" y1="20" x2="12.01" y2="20"/></svg></div><div class="stat-num skeleton" id="st-online">—</div><div class="stat-label">ออนไลน์</div></div>
          <div class="stat-card"><div class="stat-ic"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><line x1="4" y1="9" x2="20" y2="9"/><line x1="4" y1="15" x2="20" y2="15"/><line x1="10" y1="3" x2="8" y2="21"/><line x1="16" y1="3" x2="14" y2="21"/></svg></div><div class="stat-num skeleton" id="st-channels">—</div><div class="stat-label">ช่องทั้งหมด</div></div>
          <div class="stat-card"><div class="stat-ic"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="var(--purple)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2H2v10l9.29 9.29c.94.94 2.48.94 3.42 0l6.58-6.58c.94-.94.94-2.48 0-3.42L12 2Z"/><path d="M7 7h.01"/></svg></div><div class="stat-num skeleton" id="st-roles">—</div><div class="stat-label">ยศทั้งหมด</div></div>
        </div>

        <!-- Category Summary Cards -->
        <div style="font-size:11px;font-weight:700;color:var(--muted2);text-transform:uppercase;letter-spacing:.8px;margin:6px 0 10px;display:flex;align-items:center;gap:6px;"><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect width="7" height="7" x="3" y="3" rx="1"/><rect width="7" height="7" x="14" y="3" rx="1"/><rect width="7" height="7" x="14" y="14" rx="1"/><rect width="7" height="7" x="3" y="14" rx="1"/></svg> หมวดหมู่ระบบป้องกัน</div>
        <div id="category-cards" style="display:grid;grid-template-columns:repeat(2,1fr);gap:10px;margin-bottom:16px;"></div>

        <!-- Activity Charts -->
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:16px;" id="charts-row">
          <div class="card" style="padding:18px;">
            <div class="card-title" style="margin-bottom:12px;"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>ระบบที่เปิดอยู่</div>
            <div style="position:relative;height:160px;">
              <canvas id="chart-protection"></canvas>
            </div>
          </div>
          <div class="card" style="padding:18px;">
            <div class="card-title" style="margin-bottom:12px;"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>ภาพรวมเซิร์ฟเวอร์</div>
            <div style="position:relative;height:160px;">
              <canvas id="chart-server"></canvas>
            </div>
          </div>
        </div>

        <div class="card">
          <div class="card-title"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>สถานะระบบป้องกัน</div>
          <div id="system-status-list"></div>
        </div>
      </div>

      <!-- ═══ ANTI-NUKE ═══ -->
      <div class="page" id="page-antinuke">
        <div class="sec-head"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--danger)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg> Anti-Nuke — ป้องกันผู้ดูแลระบบใช้อำนาจในทางที่ผิด</div>
        <div class="feature-grid" id="grid-antinuke"></div>
      </div>

      <!-- ═══ ANTI-RAID ═══ -->
      <div class="page" id="page-antiraid">
        <div class="sec-head"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--warn)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M11 3a1 1 0 1 0 2 0 1 1 0 0 0-2 0"/><path d="M11 21a1 1 0 1 0 2 0 1 1 0 0 0-2 0"/><path d="M3 11a1 1 0 1 0 0 2 1 1 0 0 0 0-2"/><path d="M21 11a1 1 0 1 0 0 2 1 1 0 0 0 0-2"/><path d="m15.5 4.5-2 4.5H11l-2 4.5"/><path d="M12 12a1 1 0 1 0 2 0 1 1 0 0 0-2 0"/><circle cx="12" cy="12" r="9"/></svg> Anti-Raid & Gatekeeper — สกัดกั้นการโจมตีพร้อมกัน</div>
        <div class="feature-grid" id="grid-antiraid"></div>
      </div>

      <!-- ═══ LOCKDOWN ═══ -->
      <div class="page" id="page-lockdown">
        <div class="sec-head"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--danger)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg> Server Lockdown Protocol</div>
        <div class="feature-grid" id="grid-lockdown"></div>
      </div>

      <!-- ═══ ANTI-SPAM ═══ -->
      <div class="page" id="page-antispam">
        <div class="sec-head"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--primary-light)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/><line x1="9" y1="10" x2="9" y2="10"/><line x1="12" y1="10" x2="12" y2="10"/><line x1="15" y1="10" x2="15" y2="10"/></svg> Anti-Spam & Content Security</div>
        <div class="feature-grid" id="grid-antispam"></div>
      </div>

      <!-- ═══ AUTO MOD ═══ -->
      <div class="page" id="page-automod">
        <div class="sec-head"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--success)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 8V4H8"/><rect width="16" height="12" x="4" y="8" rx="2"/><path d="M2 14h2"/><path d="M20 14h2"/><path d="M15 13v2"/><path d="M9 13v2"/></svg> Auto Mod — กรองข้อความอัตโนมัติ</div>
        <div class="card">
          <div class="trow" style="padding-top:0;">
            <div class="trow-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="var(--warn)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M13 10V3L4 14h7v7l9-11h-7z"/></svg></div>
            <div class="trow-info"><div class="trow-label">เปิดใช้งาน Auto Mod</div><div class="trow-desc">ตรวจสอบและลบข้อความที่ละเมิดกฎอัตโนมัติ</div></div>
            <label class="tog"><input type="checkbox" id="am-enabled"><span class="tog-sl"></span></label>
          </div>
          <div class="trow">
            <div class="trow-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M9 17H7A5 5 0 0 1 7 7h2"/><path d="M15 7h2a5 5 0 1 1 0 10h-2"/><line x1="8" y1="12" x2="16" y2="12"/></svg></div>
            <div class="trow-info"><div class="trow-label">กรองลิงก์</div></div>
            <label class="tog"><input type="checkbox" id="am-links"><span class="tog-sl"></span></label>
          </div>
          <div class="trow">
            <div class="trow-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/><line x1="2" y1="2" x2="22" y2="22"/></svg></div>
            <div class="trow-info"><div class="trow-label">กรองลิงก์เชิญ Discord</div></div>
            <label class="tog"><input type="checkbox" id="am-invites"><span class="tog-sl"></span></label>
          </div>
          <div class="trow">
            <div class="trow-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 7 4 4 20 4 20 7"/><line x1="9" y1="20" x2="15" y2="20"/><line x1="12" y1="4" x2="12" y2="20"/></svg></div>
            <div class="trow-info"><div class="trow-label">กรองตัวพิมพ์ใหญ่ (Caps Spam)</div></div>
            <label class="tog"><input type="checkbox" id="am-caps"><span class="tog-sl"></span></label>
          </div>
          <div class="field-group" style="margin-top:12px;">
            <label class="fl-label">บทลงโทษ Auto Mod</label>
            <div class="punish-wrap" id="pun-automod"></div>
          </div>
          <div class="field-group">
            <label class="fl-label">ระยะเวลา Timeout (นาที)</label>
            <input class="input" type="number" id="am-mute-dur" min="1" max="43200" value="5"/>
          </div>
          <div class="field-group">
            <label class="fl-label">คำต้องห้าม (Enter เพื่อเพิ่ม)</label>
            <input class="input" id="bw-inp" type="text" placeholder="พิมพ์คำแล้วกด Enter..."/>
            <div class="chips-wrap" id="bw-chips"></div>
          </div>
        </div>
      </div>

      <!-- ═══ VOICE ABUSE ═══ -->
      <div class="page" id="page-voiceabuse">
        <div class="sec-head"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--purple)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2a3 3 0 0 0-3 3v7a3 3 0 0 0 6 0V5a3 3 0 0 0-3-3Z"/><path d="M19 10v2a7 7 0 0 1-14 0v-2"/><line x1="12" y1="19" x2="12" y2="22"/></svg> Voice Abuse</div>
        <div class="feature-grid" id="grid-voice"></div>
      </div>

      <!-- ═══ WELCOME ═══ -->
      <div class="page" id="page-welcome">
        <div class="card">
          <div class="card-title"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;"><path d="M13 4h3a2 2 0 0 1 2 2v14"/><path d="M2 20h3"/><path d="M13 20h9"/><path d="M10 12v.01"/><path d="M13 4.562v16.157a1 1 0 0 1-1.242.97L5 20V5.562a2 2 0 0 1 1.515-1.94l4-1A2 2 0 0 1 13 4.561Z"/></svg>ข้อความต้อนรับ</div>
          <div class="trow" style="padding-top:0;">
            <div class="trow-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M13 4h3a2 2 0 0 1 2 2v14"/><path d="M2 20h3"/><path d="M13 20h9"/><path d="M10 12v.01"/><path d="M13 4.562v16.157a1 1 0 0 1-1.242.97L5 20V5.562a2 2 0 0 1 1.515-1.94l4-1A2 2 0 0 1 13 4.561Z"/></svg></div>
            <div class="trow-info"><div class="trow-label">เปิดใช้งาน Welcome</div></div>
            <label class="tog"><input type="checkbox" id="wlc-en"><span class="tog-sl"></span></label>
          </div>
          <div class="field-group" style="margin-top:12px;">
            <label class="fl-label">Channel ID ห้อง Welcome</label>
            <input class="input" type="text" id="wlc-ch" placeholder="เช่น 1234567890123456789"/>
          </div>
          <div class="field-group">
            <label class="fl-label">ข้อความ (ใช้ {user}, {server}, {count})</label>
            <textarea class="input" id="wlc-msg" rows="3"></textarea>
          </div>
        </div>
      </div>

      <!-- ═══ WHITELIST ═══ -->
      <div class="page" id="page-whitelist">
        <div class="card">
          <div class="card-title"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="var(--success)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>Whitelist — ข้ามการตรวจสอบทั้งหมด</div>

          <!-- ── เพิ่มยศ ── -->
          <div class="field-group" style="margin-top:0;">
            <label class="fl-label">เพิ่ม / ลบ ยศ</label>
            <div style="display:flex;gap:8px;align-items:center;">
              <select class="input" id="wl-role-select" style="flex:1;">
                <option value="">⏳ กำลังโหลดยศ...</option>
              </select>
              <button class="btn btn-success btn-sm" onclick="wlAddRole()">+ เพิ่ม</button>
            </div>
            <div class="chips-wrap" id="wl-role-chips"></div>
          </div>

          <!-- ── เพิ่มสมาชิก ── -->
          <div class="field-group">
            <label class="fl-label">เพิ่ม / ลบ สมาชิก</label>
            <div style="position:relative;">
              <input class="input" type="text" id="wl-member-search"
                     placeholder="พิมพ์ชื่อ, ชื่อเล่น หรือ ID เพื่อค้นหา..."
                     autocomplete="off" oninput="wlSearchMembers(this.value)"/>
              <div id="wl-member-dropdown"
                   style="display:none;position:absolute;left:0;right:0;top:calc(100% + 4px);
                          background:var(--surface2);border:1.5px solid var(--border2);
                          border-radius:var(--r-sm);z-index:50;max-height:220px;overflow-y:auto;
                          box-shadow:0 8px 24px rgba(0,0,0,.5);">
              </div>
            </div>
            <div class="chips-wrap" id="wl-user-chips"></div>
          </div>

          <!-- ── Bot Whitelist ── -->
          <div class="field-group">
            <label class="fl-label">Bot Whitelist IDs สำหรับ Anti-Bot Add (คั่นด้วย Enter)</label>
            <textarea class="input" id="wl-bots" rows="3" placeholder="Bot IDs ที่อนุญาต..."></textarea>
          </div>
        </div>
      </div>

      <!-- ═══ LOG CHANNELS ═══ -->
      <div class="page" id="page-logchannels">
        <div class="card">
          <div class="card-title"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;"><path d="m3 11 19-9-9 19-2-8-8-2z"/></svg>Log Channels</div>
          <div class="field-group" style="margin-top:0;">
            <label class="fl-label">Log Channel หลัก (ID)</label>
            <input class="input" type="text" id="main-log-ch" placeholder="Channel ID"/>
          </div>
          <button class="btn btn-success btn-sm" style="margin-bottom:14px;" onclick="autoCreateLogs()"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="m21.64 3.64-1.28-1.28a1.21 1.21 0 0 0-1.72 0L2.36 18.64a1.21 1.21 0 0 0 0 1.72l1.28 1.28a1.2 1.2 0 0 0 1.72 0L21.64 5.36a1.2 1.2 0 0 0 0-1.72Z"/><path d="m14 7 3 3"/><path d="M5 6v4"/><path d="M19 14v4"/><path d="M10 2v2"/><path d="M7 8H3"/><path d="M21 16h-4"/><path d="M11 3H9"/></svg> สร้างห้อง Log อัตโนมัติทั้งหมด</button>
          <div class="logch-grid" id="logch-grid"></div>
        </div>
      </div>

      <!-- ═══ SETTINGS ═══ -->
      <div class="page" id="page-settings">
        <div class="card">
          <div class="card-title"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;"><path d="M20 7H9"/><path d="M14 17H3"/><circle cx="17" cy="17" r="3"/><circle cx="7" cy="7" r="3"/></svg>ตั้งค่าทั่วไป</div>
          <div class="field-group" style="margin-top:0;">
            <label class="fl-label">Blacklist Role ID (สำหรับ Quarantine)</label>
            <div style="display:flex;gap:8px;">
              <input class="input" type="text" id="bl-role-id" placeholder="วาง Role ID หรือกดสร้างอัตโนมัติ" style="flex:1;"/>
              <button class="btn btn-success btn-sm" onclick="sendInitBl()"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="m21.64 3.64-1.28-1.28a1.21 1.21 0 0 0-1.72 0L2.36 18.64a1.21 1.21 0 0 0 0 1.72l1.28 1.28a1.2 1.2 0 0 0 1.72 0L21.64 5.36a1.2 1.2 0 0 0 0-1.72Z"/><path d="m14 7 3 3"/><path d="M5 6v4"/><path d="M19 14v4"/><path d="M10 2v2"/><path d="M7 8H3"/><path d="M21 16h-4"/><path d="M11 3H9"/></svg> สร้างอัตโนมัติ</button>
            </div>
          </div>
        </div>
        <div class="card" style="margin-top:4px;">
          <div class="card-title"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>คำสั่ง Bot ที่ใช้ได้</div>
          <div style="display:flex;flex-direction:column;gap:10px;font-size:13px;">
            <div style="background:var(--surface2);border-radius:8px;padding:10px 14px;">
              <code style="color:var(--accent);font-family:'JetBrains Mono',monospace;">/getcode</code>
              <div style="color:var(--muted);font-size:12px;margin-top:3px;">รับรหัสเข้า Dashboard (เจ้าของ Server เท่านั้น)</div>
            </div>
            <div style="background:var(--surface2);border-radius:8px;padding:10px 14px;">
              <code style="color:var(--accent);font-family:'JetBrains Mono',monospace;">/initbl</code>
              <div style="color:var(--muted);font-size:12px;margin-top:3px;">สร้างยศ Blacklist สำหรับ Quarantine อัตโนมัติ</div>
            </div>
            <div style="background:var(--surface2);border-radius:8px;padding:10px 14px;">
              <code style="color:var(--accent);font-family:'JetBrains Mono',monospace;">/lockdown [on/off]</code>
              <div style="color:var(--muted);font-size:12px;margin-top:3px;">เปิด/ปิด Server Lockdown ฉุกเฉินทันที</div>
            </div>
            <div style="background:var(--surface2);border-radius:8px;padding:10px 14px;">
              <code style="color:var(--accent);font-family:'JetBrains Mono',monospace;">/whitelist add user @mention</code>
              <div style="color:var(--muted);font-size:12px;margin-top:3px;">เพิ่มสมาชิกเข้า Whitelist (ข้ามการตรวจทั้งหมด)</div>
            </div>
            <div style="background:var(--surface2);border-radius:8px;padding:10px 14px;">
              <code style="color:var(--accent);font-family:'JetBrains Mono',monospace;">/whitelist add role @role</code>
              <div style="color:var(--muted);font-size:12px;margin-top:3px;">เพิ่มยศเข้า Whitelist</div>
            </div>
            <div style="background:var(--surface2);border-radius:8px;padding:10px 14px;">
              <code style="color:var(--accent);font-family:'JetBrains Mono',monospace;">/whitelist remove user/role @x</code>
              <div style="color:var(--muted);font-size:12px;margin-top:3px;">ลบออกจาก Whitelist</div>
            </div>
            <div style="background:var(--surface2);border-radius:8px;padding:10px 14px;">
              <code style="color:var(--accent);font-family:'JetBrains Mono',monospace;">/whitelist list</code>
              <div style="color:var(--muted);font-size:12px;margin-top:3px;">ดูรายชื่อ Whitelist ทั้งหมด</div>
            </div>
          </div>
        </div>
      </div>

      <!-- ═══ LOGS ═══ -->
      <div class="page" id="page-logs">
        <div class="card" style="padding:0;">
          <div id="log-list" class="log-list" style="padding:8px;"></div>
        </div>
      </div>

      <!-- ═══ MEMBER PROFILE ═══ -->
      <div class="page" id="page-memberprofile">

        <!-- Search -->
        <div class="card" style="margin-bottom:8px;">
          <div class="card-title"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="10" r="3"/><path d="M7 20.662V19a2 2 0 0 1 2-2h6a2 2 0 0 1 2 2v1.662"/></svg>โปรไฟล์สมาชิก &amp; ตั้งค่าการยกเว้น</div>
          <div style="position:relative;">
            <input class="input" type="text" id="mp-search"
                   placeholder="พิมพ์ชื่อ, ชื่อเล่น หรือ ID เพื่อค้นหาสมาชิก..."
                   autocomplete="off" oninput="mpSearch(this.value)"/>
            <div id="mp-dropdown"
                 style="display:none;position:absolute;left:0;right:0;top:calc(100% + 4px);
                        background:var(--surface2);border:1.5px solid var(--border2);
                        border-radius:var(--r-sm);z-index:50;max-height:220px;overflow-y:auto;
                        box-shadow:0 8px 24px rgba(0,0,0,.5);"></div>
          </div>
        </div>

        <!-- Recent members list -->
        <div class="card" style="margin-bottom:8px;">
          <div style="font-size:11px;font-weight:700;color:var(--muted2);text-transform:uppercase;letter-spacing:.6px;margin-bottom:10px;"><svg xmlns="http://www.w3.org/2000/svg" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="margin-right:4px;"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>สมาชิกที่เคยดูล่าสุด</div>
          <div id="mp-recent-list">
            <div style="color:var(--muted);font-size:13px;text-align:center;padding:18px 0;">ยังไม่มีประวัติการดู — ค้นหาและเลือกสมาชิกด้านบน</div>
          </div>
        </div>

        <!-- Profile panel (hidden until member selected) -->
        <div id="mp-panel" style="display:none;">
          <div class="card" style="margin-bottom:8px;">
            <div style="display:flex;align-items:center;gap:14px;margin-bottom:14px;">
              <img id="mp-avatar" src="" alt=""
                   style="width:62px;height:62px;border-radius:50%;border:2px solid var(--border2);flex-shrink:0;"/>
              <div style="flex:1;min-width:0;">
                <div id="mp-name" style="font-size:16px;font-weight:700;color:#fff;"></div>
                <div id="mp-username" style="font-size:12px;color:var(--muted);"></div>
                <div id="mp-id" style="font-size:11px;color:var(--muted2);font-family:'JetBrains Mono',monospace;margin-top:2px;"></div>
              </div>
              <!-- Gear icon → exemptions panel -->
              <button onclick="mpToggleSettings()" title="ตั้งค่าการยกเว้น"
                      style="background:var(--surface2);border:1px solid var(--border);border-radius:8px;
                             padding:8px 10px;font-size:18px;cursor:pointer;flex-shrink:0;
                             transition:all .15s;" id="mp-gear-btn"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/><circle cx="12" cy="12" r="3"/></svg></button>
            </div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:14px;">
              <div style="background:var(--surface2);border-radius:8px;padding:10px;">
                <div style="font-size:10px;color:var(--muted2);font-weight:700;text-transform:uppercase;letter-spacing:.5px;">เข้าร่วมเซิร์ฟเวอร์</div>
                <div id="mp-joined" style="font-size:12px;color:var(--text);margin-top:3px;"></div>
              </div>
              <div style="background:var(--surface2);border-radius:8px;padding:10px;">
                <div style="font-size:10px;color:var(--muted2);font-weight:700;text-transform:uppercase;letter-spacing:.5px;">สร้างบัญชี</div>
                <div id="mp-created" style="font-size:12px;color:var(--text);margin-top:3px;"></div>
              </div>
            </div>
            <div>
              <div style="font-size:11px;font-weight:700;color:var(--muted2);text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px;">ยศที่มี</div>
              <div id="mp-roles" class="chips-wrap" style="margin-top:0;"></div>
            </div>
          </div>

          <!-- Exemption settings (hidden until gear pressed) -->
          <div class="card" id="mp-settings-panel" style="display:none;margin-bottom:8px;">
            <div class="card-title"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="var(--primary-light)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>ตั้งค่าการยกเว้นการป้องกัน</div>
            <div style="font-size:12px;color:var(--muted);margin-bottom:14px;">เลือกว่าสมาชิกคนนี้จะถูกยกเว้นจากระบบป้องกันใดบ้าง</div>
            <div class="trow" style="padding-top:0;">
              <div class="trow-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="var(--success)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg></div>
              <div class="trow-info"><div class="trow-label">ยกเว้นทั้งหมด (Whitelist เต็ม)</div><div class="trow-desc">ข้ามการตรวจสอบทุกอย่างเหมือนเจ้าของเซิร์ฟเวอร์</div></div>
              <label class="tog"><input type="checkbox" id="ex-all" onchange="exToggleAll(this)"><span class="tog-sl"></span></label>
            </div>
            <div class="trow">
              <div class="trow-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/><line x1="12" y1="7" x2="12" y2="11"/><line x1="12" y1="15" x2="12.01" y2="15"/></svg></div>
              <div class="trow-info"><div class="trow-label">ยกเว้น Anti-Spam</div><div class="trow-desc">ไม่ถูกตรวจจับว่าสแปมข้อความ</div></div>
              <label class="tog"><input type="checkbox" id="ex-spam"><span class="tog-sl"></span></label>
            </div>
            <div class="trow">
              <div class="trow-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg></div>
              <div class="trow-info"><div class="trow-label">ยกเว้น Anti-Link Spam</div><div class="trow-desc">สามารถส่งลิงก์ได้โดยไม่ถูกลงโทษ</div></div>
              <label class="tog"><input type="checkbox" id="ex-links"><span class="tog-sl"></span></label>
            </div>
            <div class="trow">
              <div class="trow-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M16 8v5a3 3 0 0 0 6 0v-1a10 10 0 1 0-3.92 7.94"/></svg></div>
              <div class="trow-info"><div class="trow-label">ยกเว้น Anti-Mass Mentions</div><div class="trow-desc">แท็กสมาชิกจำนวนมากได้</div></div>
              <label class="tog"><input type="checkbox" id="ex-mentions"><span class="tog-sl"></span></label>
            </div>
            <div class="trow">
              <div class="trow-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M11 3a1 1 0 1 0 2 0 1 1 0 0 0-2 0"/><path d="M11 21a1 1 0 1 0 2 0 1 1 0 0 0-2 0"/><path d="M3 11a1 1 0 1 0 0 2 1 1 0 0 0 0-2"/><path d="M21 11a1 1 0 1 0 0 2 1 1 0 0 0 0-2"/><circle cx="12" cy="12" r="9"/></svg></div>
              <div class="trow-info"><div class="trow-label">ยกเว้น Anti-Raid / Gatekeeper</div><div class="trow-desc">ไม่ถูกเตะเพราะบัญชีใหม่หรือ join flood</div></div>
              <label class="tog"><input type="checkbox" id="ex-raid"><span class="tog-sl"></span></label>
            </div>
            <div class="trow">
              <div class="trow-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg></div>
              <div class="trow-info"><div class="trow-label">ยกเว้น Anti-Nuke</div><div class="trow-desc">ไม่ถูกตรวจจับการลบห้อง/ยศ/แบนสมาชิก</div></div>
              <label class="tog"><input type="checkbox" id="ex-nuke"><span class="tog-sl"></span></label>
            </div>
            <div class="trow">
              <div class="trow-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 8V4H8"/><rect width="16" height="12" x="4" y="8" rx="2"/><path d="M2 14h2"/><path d="M20 14h2"/><path d="M15 13v2"/><path d="M9 13v2"/></svg></div>
              <div class="trow-info"><div class="trow-label">ยกเว้น Auto Mod</div><div class="trow-desc">ไม่ถูกกรองคำต้องห้าม/ลิงก์/emoji</div></div>
              <label class="tog"><input type="checkbox" id="ex-automod"><span class="tog-sl"></span></label>
            </div>
            <div class="trow">
              <div class="trow-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2a3 3 0 0 0-3 3v7a3 3 0 0 0 6 0V5a3 3 0 0 0-3-3Z"/><path d="M19 10v2a7 7 0 0 1-14 0v-2"/><line x1="12" y1="19" x2="12" y2="22"/></svg></div>
              <div class="trow-info"><div class="trow-label">ยกเว้น Voice Abuse</div><div class="trow-desc">ไม่ถูกตรวจจับการย้ายคนใน Voice</div></div>
              <label class="tog"><input type="checkbox" id="ex-voice"><span class="tog-sl"></span></label>
            </div>
            <div style="margin-top:14px;display:flex;gap:8px;">
              <button class="btn btn-primary" style="flex:1;" onclick="mpSaveExemptions()"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg> บันทึกการตั้งค่า</button>
              <button class="btn btn-danger btn-sm" onclick="mpClearExemptions()"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></svg> รีเซ็ต</button>
            </div>
          </div>

          <!-- Suspicious Behavior -->
          <div class="card" id="mp-suspicious-panel">
            <div class="card-title"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="var(--warn)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;"><path d="M5.5 8.5 9 12l-3.5 3.5L2 12l3.5-3.5Z"/><path d="m12 2 3.5 3.5L12 9 8.5 5.5 12 2Z"/><path d="M18.5 8.5 22 12l-3.5 3.5L15 12l3.5-3.5Z"/><path d="m12 15 3.5 3.5L12 22l-3.5-3.5L12 15Z"/></svg>พฤติกรรมน่าสงสัย</div>
            <div id="mp-suspicious-list">
              <div style="color:var(--muted);font-size:13px;text-align:center;padding:18px 0;">กำลังวิเคราะห์...</div>
            </div>
          </div>
        </div>
      </div>

      <!-- ═══ SUSPICIOUS BEHAVIOR ALERTS ═══ -->
      <div class="page" id="page-suspicious">
        <div class="card" style="margin-bottom:8px;">
          <div class="card-title"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>แจ้งเตือนพฤติกรรมน่าสงสัย</div>
          <div style="font-size:12px;color:var(--muted);margin-bottom:8px;">บอทตรวจจับพฤติกรรมผิดปกติและแสดงที่นี่ ไม่มีบทลงโทษ — เพียงแจ้งให้ Admin ทราบ</div>
          <div style="display:flex;gap:6px;margin-bottom:4px;">
            <button class="btn btn-sm" id="sus-filter-all" onclick="susFilter('all')" style="flex:1;">ทั้งหมด</button>
            <button class="btn btn-sm" id="sus-filter-high" onclick="susFilter('high')" style="flex:1;color:#ff4757;"><span class="sus-dot" style="background:var(--danger);"></span>สูง</button>
            <button class="btn btn-sm" id="sus-filter-med" onclick="susFilter('med')" style="flex:1;color:#ffa502;"><span class="sus-dot" style="background:var(--warn);"></span>กลาง</button>
            <button class="btn btn-sm" id="sus-filter-low" onclick="susFilter('low')" style="flex:1;color:var(--success);"><span class="sus-dot" style="background:var(--success);"></span>ต่ำ</button>
          </div>
        </div>
        <div id="sus-alert-list" style="display:flex;flex-direction:column;gap:8px;">
          <div style="color:var(--muted);font-size:13px;text-align:center;padding:30px 0;">⏳ กำลังโหลด...</div>
        </div>
      </div>

      <!-- ═══ ROLE INSPECTOR ═══ -->
      <div class="page" id="page-roleinspector">
        <div class="card" style="margin-bottom:8px;">
          <div class="card-title"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;"><path d="M12 2H2v10l9.29 9.29c.94.94 2.48.94 3.42 0l6.58-6.58c.94-.94.94-2.48 0-3.42L12 2Z"/><path d="M7 7h.01"/></svg>Role Inspector — ดูสิทธิ์ห้องของยศ</div>
          <div style="font-size:12px;color:var(--muted);margin-bottom:12px;">เลือกยศเพื่อดูว่ายศนั้นเห็น/พิมพ์ในห้องใดได้บ้าง</div>
          <div id="ri-role-list" style="display:flex;flex-direction:column;gap:6px;"></div>
        </div>

        <!-- Channel permission panel -->
        <div id="ri-panel" style="display:none;">
          <div class="card">
            <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;">
              <div>
                <div id="ri-role-name" style="font-size:15px;font-weight:700;color:#fff;"></div>
                <div style="font-size:11px;color:var(--muted);margin-top:2px;">
                  <span id="ri-can-count" style="color:var(--success);font-weight:600;"></span>
                  <span style="margin:0 6px;">•</span>
                  <span id="ri-cant-count" style="color:var(--danger);font-weight:600;"></span>
                </div>
              </div>
              <button class="btn btn-sm" onclick="riClose()"><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg> ปิด</button>
            </div>

            <!-- Filter -->
            <div style="display:flex;gap:6px;margin-bottom:12px;">
              <button class="btn btn-sm" id="ri-filter-all" onclick="riFilter('all')" style="flex:1;">ทั้งหมด</button>
              <button class="btn btn-sm" id="ri-filter-can" onclick="riFilter('can')" style="flex:1;color:var(--success);"><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg> เห็น</button>
              <button class="btn btn-sm" id="ri-filter-cant" onclick="riFilter('cant')" style="flex:1;color:var(--danger);"><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg> ไม่เห็น</button>
            </div>

            <div id="ri-channel-list" style="display:flex;flex-direction:column;gap:4px;max-height:480px;overflow-y:auto;"></div>
          </div>
        </div>
      </div>

    </div><!-- /main-body -->
  </div><!-- /main -->

  <!-- BOTTOM NAV -->
  <nav id="bottom-nav">
    <div class="bnav-inner">
      <div class="bnav-item active" onclick="goPage('home')"><div class="bnav-ic"><svg xmlns="http://www.w3.org/2000/svg" width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect width="7" height="9" x="3" y="3" rx="1"/><rect width="7" height="5" x="14" y="3" rx="1"/><rect width="7" height="9" x="14" y="12" rx="1"/><rect width="7" height="5" x="3" y="16" rx="1"/></svg></div>หลัก</div>
      <div class="bnav-item" onclick="goPage('antinuke')"><div class="bnav-ic"><svg xmlns="http://www.w3.org/2000/svg" width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg></div>Nuke</div>
      <div class="bnav-item" onclick="goPage('antiraid')"><div class="bnav-ic"><svg xmlns="http://www.w3.org/2000/svg" width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M11 3a1 1 0 1 0 2 0 1 1 0 0 0-2 0"/><path d="M11 21a1 1 0 1 0 2 0 1 1 0 0 0-2 0"/><path d="M3 11a1 1 0 1 0 0 2 1 1 0 0 0 0-2"/><path d="M21 11a1 1 0 1 0 0 2 1 1 0 0 0 0-2"/><circle cx="12" cy="12" r="9"/></svg></div>Raid</div>
      <div class="bnav-item" onclick="goPage('antispam')"><div class="bnav-ic"><svg xmlns="http://www.w3.org/2000/svg" width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/><line x1="9" y1="10" x2="9" y2="10"/><line x1="12" y1="10" x2="12" y2="10"/><line x1="15" y1="10" x2="15" y2="10"/></svg></div>Spam</div>
      <div class="bnav-item" onclick="goPage('settings')"><div class="bnav-ic"><svg xmlns="http://www.w3.org/2000/svg" width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/><circle cx="12" cy="12" r="3"/></svg></div>ตั้งค่า</div>
    </div>
  </nav>
</div><!-- /app-view -->

<script>
// ─── CONFIG ───────────────────────────────────────────────────────
const API_BASE = "http://localhost:8080";
let CFG = {};
let logChConfig = {};
let savedWords = [];
let wlRoleIds  = [];
let wlUserIds  = [];
let wlRoleData = [];
let wlUserData = {};

const getToken = () => sessionStorage.getItem('sb_token') || '';
const setToken = t => sessionStorage.setItem('sb_token', t);

// ─── PUNISHMENT OPTIONS ───────────────────────────────────────────
const PUNISHMENTS = [
  {val:'ban',        ic:'<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 3H5a2 2 0 0 0-2 2v4m6-6h10a2 2 0 0 1 2 2v4M9 3v11m0 0H5a2 2 0 0 1-2-2V9m6 5h10a2 2 0 0 0 2-2V9m0 0H3"/></svg>', label:'แบน',        cls:'p-ban'},
  {val:'kick',       ic:'<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 0 1-3 3H6a3 3 0 0 1-3-3V7a3 3 0 0 1 3-3h4a3 3 0 0 1 3 3v1"/></svg>', label:'เตะ',         cls:'p-kick'},
  {val:'quarantine', ic:'<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>', label:'กักบริเวณ',  cls:'p-quarantine'},
  {val:'timeout',    ic:'<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>', label:'Timeout',    cls:'p-timeout'},
  {val:'log',        ic:'<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><line x1="10" y1="9" x2="8" y2="9"/></svg>', label:'Log Only',   cls:'p-log'},
];

function buildPunishWrap(wrapperId, currentVal) {
  const wrap = document.getElementById(wrapperId);
  if (!wrap) return;
  wrap.dataset.val = currentVal || 'timeout';
  wrap.innerHTML = PUNISHMENTS.map(p => `
    <div class="punish-btn ${p.cls} ${currentVal===p.val?'sel':''}"
         onclick="(function(el){
           document.getElementById('${wrapperId}').querySelectorAll('.punish-btn').forEach(b=>b.classList.remove('sel'));
           el.classList.add('sel');
           document.getElementById('${wrapperId}').dataset.val='${p.val}';
         })(this)">
      <div class="punish-ic">${p.ic}</div>${p.label}
    </div>`).join('');
}

// ─── FEATURE CARD BUILDER ─────────────────────────────────────────
// Each feature gets its own card with: toggle, limit, window, punishment
function buildFeatureCard(key, emoji, name, desc, cfg, extraFields='') {
  const feat = cfg[key] || {};
  const checked = feat.enabled ? 'checked' : '';
  const limit  = feat.limit  ?? 3;
  const window_ = feat.window ?? 10;
  const punish  = feat.punishment || 'ban';
  const punishOpts = PUNISHMENTS.map(p =>
    `<div class="punish-btn ${p.cls} ${punish===p.val?'sel':''}"
       onclick="selectFeatPunish('${key}',this,'${p.val}','${p.cls}')" >
       <div class="punish-ic">${p.ic}</div>${p.label}
     </div>`).join('');

  return `
  <div class="feat-card ${feat.enabled?'enabled':''}" id="fcard-${key}">
    <div class="feat-header">
      <div class="feat-emoji">${emoji}</div>
      <div class="feat-label">
        <div class="feat-name">${name}</div>
        <div class="feat-desc">${desc}</div>
      </div>
      <label class="tog">
        <input type="checkbox" id="feat-en-${key}" ${checked}
               onchange="toggleFeatCard('${key}',this.checked)">
        <span class="tog-sl"></span>
      </label>
    </div>
    <div class="feat-body">
      <div class="sub-field">
        <div class="sub-label">บทลงโทษ</div>
        <div class="punish-wrap" id="punish-${key}" data-val="${punish}">${punishOpts}</div>
      </div>
      <div class="sub-field">
        <div class="sub-label">ขีดจำกัดจำนวนครั้ง (Threshold)</div>
        <div class="sub-row">
          <input class="sub-input" type="number" id="feat-limit-${key}" min="1" max="100" value="${limit}">
          <span class="sub-unit">ครั้ง</span>
        </div>
      </div>
      <div class="sub-field">
        <div class="sub-label">ช่วงเวลา (Time Window)</div>
        <div class="sub-row">
          <input class="sub-input" type="number" id="feat-window-${key}" min="1" max="3600" value="${window_}">
          <span class="sub-unit">วินาที</span>
        </div>
      </div>
      ${extraFields}
    </div>
    <div class="adv-toggle-row" id="adv-row-${key}">
      <div class="adv-toggle-ic">
        <svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12h6"/><path d="M12 9v6"/></svg>
      </div>
      <div class="adv-toggle-info">
        <div class="adv-toggle-label">จัดการขั้นสูง</div>
        <div class="adv-toggle-desc">ปิด permission ผู้ดูแลทันที &#x2192; ตรวจ &#x2192; ลงโทษ &#x2192; คืนอัตโนมัติ</div>
      </div>
      <label class="tog">
        <input type="checkbox" id="adv-en-${key}"
               onchange="onAdvToggle('${key}', this.checked)">
        <span class="tog-sl"></span>
      </label>
    </div>
  </div>`;
}

function toggleFeatCard(key, on) {
  const card = document.getElementById('fcard-' + key);
  if (card) card.classList.toggle('enabled', on);
}

function selectFeatPunish(key, el, val, cls) {
  const wrap = document.getElementById('punish-' + key);
  wrap.querySelectorAll('.punish-btn').forEach(b => b.classList.remove('sel'));
  el.classList.add('sel');
  wrap.dataset.val = val;
}

// ─── ADVANCED MANAGE TOGGLE ──────────────────────────────────────
async function onAdvToggle(featureKey, enabled) {
  try {
    const res = await fetch(`${API_BASE}/api/advanced-manage?token=${getToken()}`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ feature_key: featureKey, enabled: enabled }),
    });
    const data = await res.json();
    if (data.success) {
      toast(
        enabled
          ? `✅ เปิดโหมดจัดการขั้นสูง — เมื่อเกิดเหตุจะปิด permission ก่อนทันที`
          : `🔓 ปิดโหมดจัดการขั้นสูง — กลับสู่การตรวจจับปกติ`,
        'success'
      );
    } else {
      toast(`❌ ${data.error || 'เกิดข้อผิดพลาด'}`, 'error');
      // revert toggle
      const cb = document.getElementById('adv-en-' + featureKey);
      if (cb) cb.checked = !enabled;
    }
  } catch (err) {
    toast(`❌ เชื่อมต่อไม่ได้: ${err.message}`, 'error');
    const cb = document.getElementById('adv-en-' + featureKey);
    if (cb) cb.checked = !enabled;
  }
}

function getFeatVal(key) {
  const en     = document.getElementById('feat-en-' + key);
  const limit  = document.getElementById('feat-limit-' + key);
  const window_= document.getElementById('feat-window-' + key);
  const pwrap  = document.getElementById('punish-' + key);
  const advEn  = document.getElementById('adv-en-' + key);
  return {
    enabled:    en     ? en.checked               : false,
    limit:      limit  ? parseInt(limit.value)||3  : 3,
    window:     window_? parseInt(window_.value)||10: 10,
    punishment: pwrap  ? (pwrap.dataset.val||'ban') : 'ban',
    _adv_mode:  advEn  ? advEn.checked             : false,
  };
}

// ─── RENDER PAGES ─────────────────────────────────────────────────
function renderAllPages(cfg) {
  renderAntiNuke(cfg);
  renderAntiRaid(cfg);
  renderLockdown(cfg);
  renderAntiSpam(cfg);
  renderVoice(cfg);
  setTimeout(() => { if (window.lucide) lucide.createIcons(); }, 50);
}

function renderAntiNuke(cfg) {
  const FEATURES = [
    {key:'anti_ban',         emoji:'<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><line x1="17" y1="8" x2="23" y2="14"/><line x1="23" y1="8" x2="17" y2="14"/></svg>',        name:'Anti-Ban Member',                 desc:'ป้องกันการกดแบนสมาชิกถี่เกินไป'},
    {key:'anti_kick',        emoji:'<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><line x1="22" y1="11" x2="16" y2="11"/></svg>',     name:'Anti-Kick Member',                desc:'ป้องกันการกดเตะสมาชิกถี่เกินไป'},
    {key:'anti_ch_create',   emoji:'<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/><line x1="12" y1="11" x2="12" y2="17"/><line x1="9" y1="14" x2="15" y2="14"/></svg>',    name:'Anti-Channel Create',             desc:'ป้องกันการสร้างห้องรัวๆ'},
    {key:'anti_ch_delete',   emoji:'<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/><line x1="9" y1="14" x2="15" y2="14"/></svg>',   name:'Anti-Channel Delete',             desc:'ป้องกันการลบห้องรัวๆ'},
    {key:'anti_ch_update',   emoji:'<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/><polyline points="16 3 12 7 8 3"/></svg>',    name:'Anti-Channel Update',             desc:'ป้องกันการแก้ไขห้องถี่เกินไป'},
    {key:'anti_role_create', emoji:'<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2H2v10l9.29 9.29c.94.94 2.48.94 3.42 0l6.58-6.58c.94-.94.94-2.48 0-3.42L12 2Z"/><path d="M7 7h.01"/><line x1="12" y1="12" x2="16" y2="12"/><line x1="14" y1="10" x2="14" y2="14"/></svg>',            name:'Anti-Role Create',                desc:'ป้องกันการสร้างยศรัวๆ'},
    {key:'anti_role_delete', emoji:'<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2H2v10l9.29 9.29c.94.94 2.48.94 3.42 0l6.58-6.58c.94-.94.94-2.48 0-3.42L12 2Z"/><path d="M7 7h.01"/><line x1="11" y1="12" x2="16" y2="12"/></svg>',       name:'Anti-Role Delete',                desc:'ป้องกันการลบยศรัวๆ'},
    {key:'anti_role_update', emoji:'<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2H2v10l9.29 9.29c.94.94 2.48.94 3.42 0l6.58-6.58c.94-.94.94-2.48 0-3.42L12 2Z"/><path d="M7 7h.01"/><path d="M20.49 15.49a9 9 0 1 1-2.12-9.36L23 10.5"/><path d="M23 4v6.5h-6.5"/></svg>',     name:'Anti-Role Update',                desc:'ป้องกันการแก้ไขยศถี่เกินไป'},
    {key:'anti_role_give',   emoji:'<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>', name:'Anti-Role Give (Dangerous Perm)', desc:'ป้องกันการแจกยศที่มีสิทธิ์อันตราย'},
    {key:'anti_webhook_create',emoji:'<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="5" r="3"/><path d="M6.5 8a2 2 0 0 0-1.905 1.46L2.1 18.5A2 2 0 0 0 4 21h16a2 2 0 0 0 1.925-2.54L19.4 9.46A2 2 0 0 0 17.5 8"/><path d="M8 12a4 4 0 0 1 8 0"/></svg>',      name:'Anti-Webhook Create',             desc:'ป้องกันการสร้าง Webhook แปลกปลอม'},
    {key:'anti_webhook_delete',emoji:'<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="5" r="3"/><path d="M6.5 8a2 2 0 0 0-1.905 1.46L2.1 18.5A2 2 0 0 0 4 21h16a2 2 0 0 0 1.925-2.54L19.4 9.46A2 2 0 0 0 17.5 8"/><line x1="9" y1="14" x2="15" y2="14"/></svg>',      name:'Anti-Webhook Delete',             desc:'ป้องกันการลบ Webhook รัวๆ'},
    {key:'anti_bot_add',     emoji:'<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 8V4H8"/><rect width="16" height="12" x="4" y="8" rx="2"/><path d="M2 14h2"/><path d="M20 14h2"/><path d="M15 13v2"/><path d="M9 13v2"/></svg>',            name:'Anti-Bot Add',                   desc:'ตรวจจับและจัดการบอทที่ถูกเชิญโดยไม่ได้รับอนุญาต'},
    {key:'anti_guild_update',emoji:'<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect width="20" height="8" x="2" y="2" rx="2" ry="2"/><rect width="20" height="8" x="2" y="14" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>',         name:'Anti-Guild Update',               desc:'ป้องกันการเปลี่ยนชื่อ/ไอคอนเซิร์ฟเวอร์'},
    {key:'anti_vanity',      emoji:'<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M9 17H7A5 5 0 0 1 7 7h2"/><path d="M15 7h2a5 5 0 1 1 0 10h-2"/><line x1="8" y1="12" x2="16" y2="12"/></svg>',         name:'Anti-Vanity URL',                desc:'ป้องกันการเปลี่ยน/ลบ Vanity URL (ดึงกลับทันที)'},
    {key:'anti_prune',       emoji:'<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="6" cy="6" r="3"/><path d="M8.12 8.12 12 12"/><path d="M20 4 8.12 15.88"/><circle cx="18" cy="18" r="3"/><path d="M11.88 11.88 16 16"/></svg>',       name:'Anti-Prune Members',              desc:'ป้องกันการ Prune สมาชิกกะทันหัน'},
    {key:'anti_integration', emoji:'<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22V12"/><path d="m17 7-5-5-5 5"/><path d="M17 22H7a2 2 0 0 1-2-2v-2a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2v2a2 2 0 0 1-2 2z"/></svg>',           name:'Anti-Integration Create/Update',  desc:'ป้องกันการเชื่อมต่อแอปภายนอกที่น่าสงสัย'},
  ];
  const grid = document.getElementById('grid-antinuke');
  grid.innerHTML = FEATURES.map(f => buildFeatureCard(f.key, f.emoji, f.name, f.desc, cfg)).join('');
}

function renderAntiRaid(cfg) {
  const grid = document.getElementById('grid-antiraid');

  // Anti-Join Flood — standard card
  const floodHtml = buildFeatureCard('anti_join_flood', '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M2 6c.6.5 1.2 1 2.5 1C7 7 7 5 9.5 5c2.6 0 2.4 2 5 2 2.5 0 2.5-2 5-2 1.3 0 1.9.5 2.5 1"/><path d="M2 12c.6.5 1.2 1 2.5 1 2.5 0 2.5-2 5-2 2.6 0 2.4 2 5 2 2.5 0 2.5-2 5-2 1.3 0 1.9.5 2.5 1"/><path d="M2 18c.6.5 1.2 1 2.5 1 2.5 0 2.5-2 5-2 2.6 0 2.4 2 5 2 2.5 0 2.5-2 5-2 1.3 0 1.9.5 2.5 1"/></svg>',
    'Anti-Join Flood (Mass Join)',
    'ตรวจจับบัญชีจำนวนมากเข้าร่วมพร้อมกัน', cfg);

  // Anti-Account Age — Threshold = min days, Window ไม่มีความหมาย → ซ่อน window
  const ageFeat   = cfg['anti_account_age'] || {};
  const agePunish = ageFeat.punishment || 'kick';
  const ageOpts   = PUNISHMENTS.map(p =>
    `<div class="punish-btn ${p.cls} ${agePunish===p.val?'sel':''}"
       onclick="selectFeatPunish('anti_account_age',this,'${p.val}','${p.cls}')">
       <div class="punish-ic">${p.ic}</div>${p.label}
     </div>`).join('');
  const ageHtml = `
  <div class="feat-card ${ageFeat.enabled?'enabled':''}" id="fcard-anti_account_age">
    <div class="feat-header">
      <div class="feat-emoji"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21 7.5V6a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h3.5"/><path d="M16 2v4"/><path d="M8 2v4"/><path d="M3 10h5"/><circle cx="18" cy="18" r="4"/><path d="M18 16.5V18l1 1"/></svg></div>
      <div class="feat-label">
        <div class="feat-name">Anti-Account Age (Alt Detector)</div>
        <div class="feat-desc">ดีดออกทันทีหากบัญชีอายุน้อยกว่าที่กำหนด</div>
      </div>
      <label class="tog">
        <input type="checkbox" id="feat-en-anti_account_age" ${ageFeat.enabled?'checked':''}
               onchange="toggleFeatCard('anti_account_age',this.checked)">
        <span class="tog-sl"></span>
      </label>
    </div>
    <div class="feat-body">
      <div class="sub-field">
        <div class="sub-label">บทลงโทษ</div>
        <div class="punish-wrap" id="punish-anti_account_age" data-val="${agePunish}">${ageOpts}</div>
      </div>
      <div class="sub-field">
        <div class="sub-label">อายุบัญชีขั้นต่ำ (วัน)</div>
        <div class="sub-row">
          <input class="sub-input" type="number" id="feat-limit-anti_account_age"
                 min="1" max="365" value="${ageFeat.limit ?? 7}">
          <span class="sub-unit">วัน</span>
        </div>
      </div>
    </div>
  </div>`;

  // Anti-Default Avatar — ไม่ต้องการ Threshold / Window
  const avFeat   = cfg['anti_no_avatar'] || {};
  const avPunish = avFeat.punishment || 'kick';
  const avOpts   = PUNISHMENTS.map(p =>
    `<div class="punish-btn ${p.cls} ${avPunish===p.val?'sel':''}"
       onclick="selectFeatPunish('anti_no_avatar',this,'${p.val}','${p.cls}')">
       <div class="punish-ic">${p.ic}</div>${p.label}
     </div>`).join('');
  const avHtml = `
  <div class="feat-card ${avFeat.enabled?'enabled':''}" id="fcard-anti_no_avatar">
    <div class="feat-header">
      <div class="feat-emoji"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="10" r="3"/><path d="M7 20.662V19a2 2 0 0 1 2-2h6a2 2 0 0 1 2 2v1.662"/></svg></div>
      <div class="feat-label">
        <div class="feat-name">Anti-Default Avatar Join</div>
        <div class="feat-desc">คัดกรองบัญชีที่ไม่มีรูปโปรไฟล์ (รูปดีฟอลต์ Discord)</div>
      </div>
      <label class="tog">
        <input type="checkbox" id="feat-en-anti_no_avatar" ${avFeat.enabled?'checked':''}
               onchange="toggleFeatCard('anti_no_avatar',this.checked)">
        <span class="tog-sl"></span>
      </label>
    </div>
    <div class="feat-body">
      <div class="sub-field">
        <div class="sub-label">บทลงโทษ</div>
        <div class="punish-wrap" id="punish-anti_no_avatar" data-val="${avPunish}">${avOpts}</div>
      </div>
    </div>
  </div>`;

  grid.innerHTML = floodHtml + ageHtml + avHtml;
}

function renderLockdown(cfg) {
  const ld = cfg['server_lockdown'] || {};
  const grid = document.getElementById('grid-lockdown');
  grid.innerHTML = `
  <div class="feat-card ${ld.enabled?'enabled':''}" id="fcard-server_lockdown">
    <div class="feat-header">
      <div class="feat-emoji"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg></div>
      <div class="feat-label">
        <div class="feat-name">Server Lockdown Protocol</div>
        <div class="feat-desc">ปิดการพิมพ์ทุกห้องและยกเลิกลิงก์เชิญทันที</div>
      </div>
      <label class="tog">
        <input type="checkbox" id="feat-en-server_lockdown" ${ld.enabled?'checked':''}
               onchange="toggleFeatCard('server_lockdown',this.checked)">
        <span class="tog-sl"></span>
      </label>
    </div>
    <div class="feat-body">
      <div style="font-size:12px;color:var(--warn);background:var(--warn-dim);border:1px solid rgba(255,165,2,.2);border-radius:8px;padding:10px 12px;">
        เปิดสวิตช์นี้จะล็อกทุกห้องทันที กด "บันทึก" เพื่อยืนยัน
      </div>
      <button class="btn btn-danger btn-full" onclick="toggleLockdown(true)"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg> เปิด Lockdown ทันที</button>
      <button class="btn btn-success btn-full" onclick="toggleLockdown(false)"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/></svg> ปิด Lockdown ทันที</button>
    </div>
  </div>`;
}

function renderAntiSpam(cfg) {
  const FEATURES = [
    {key:'anti_mass_mentions', emoji:'<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M16 8v5a3 3 0 0 0 6 0v-1a10 10 0 1 0-3.92 7.94"/></svg>', name:'Anti-Mass Mentions',
     desc:'ตรวจจับการแท็กสมาชิกจำนวนมากในข้อความเดียว (@everyone / @here / แท็กรายคน)'},
    {key:'anti_text_spam',     emoji:'<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="m17 2 4 4-4 4"/><path d="M3 11V9a4 4 0 0 1 4-4h14"/><path d="m7 22-4-4 4-4"/><path d="M21 13v2a4 4 0 0 1-4 4H3"/></svg>', name:'Anti-Text Spam',
     desc:'ตรวจจับการส่งข้อความซ้ำๆ ถี่ๆ'},
    {key:'anti_link_spam',     emoji:'<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M9 17H7A5 5 0 0 1 7 7h2"/><path d="M15 7h2a5 5 0 1 1 0 10h-2"/><line x1="8" y1="12" x2="16" y2="12"/></svg>', name:'Anti-Link & Invite Spam',
     desc:'ตรวจจับการส่งลิงก์เชิญหรือ URL อันตราย'},
    {key:'anti_att_spam',      emoji:'<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="m21.44 11.05-9.19 9.19a6 6 0 0 1-8.49-8.49l8.57-8.57A4 4 0 1 1 18 8.84l-8.59 8.57a2 2 0 0 1-2.83-2.83l8.49-8.48"/></svg>', name:'Anti-Attachment/Media Spam',
     desc:'ตรวจจับการส่งไฟล์ ภาพ หรือสติกเกอร์รัวๆ'},
    {key:'anti_emoji_spam',    emoji:'<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M8 14s1.5 2 4 2 4-2 4-2"/><line x1="9" y1="9" x2="9.01" y2="9"/><line x1="15" y1="9" x2="15.01" y2="9"/></svg>', name:'Anti-Emoji/Reaction Spam',
     desc:'ตรวจจับการกดรีแอคชั่นหรือส่ง emoji รัวๆ'},
  ];
  const grid = document.getElementById('grid-antispam');
  grid.innerHTML = FEATURES.map(f => buildFeatureCard(f.key, f.emoji, f.name, f.desc, cfg)).join('');
}

function renderVoice(cfg) {
  const feat = cfg['voiceabuse'] || {};
  const punish = feat.punishment || 'timeout';
  const punishOpts = PUNISHMENTS.map(p =>
    `<div class="punish-btn ${p.cls} ${punish===p.val?'sel':''}"
       onclick="selectFeatPunish('voiceabuse',this,'${p.val}','${p.cls}')">
       <div class="punish-ic">${p.ic}</div>${p.label}
     </div>`).join('');
  document.getElementById('grid-voice').innerHTML = `
  <div class="feat-card ${feat.enabled?'enabled':''}" id="fcard-voiceabuse">
    <div class="feat-header">
      <div class="feat-emoji"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2a3 3 0 0 0-3 3v7a3 3 0 0 0 6 0V5a3 3 0 0 0-3-3Z"/><path d="M19 10v2a7 7 0 0 1-14 0v-2"/><line x1="12" y1="19" x2="12" y2="22"/></svg></div>
      <div class="feat-label">
        <div class="feat-name">Voice Abuse Detection</div>
        <div class="feat-desc">ตรวจจับการ mute/move/disconnect สมาชิกใน Voice Channel รัวๆ</div>
      </div>
      <label class="tog">
        <input type="checkbox" id="feat-en-voiceabuse" ${feat.enabled?'checked':''}
               onchange="toggleFeatCard('voiceabuse',this.checked)">
        <span class="tog-sl"></span>
      </label>
    </div>
    <div class="feat-body">
      <div class="sub-field">
        <div class="sub-label">บทลงโทษ</div>
        <div class="punish-wrap" id="punish-voiceabuse" data-val="${punish}">${punishOpts}</div>
      </div>
      <div class="sub-field">
        <div class="sub-label">จำนวนครั้งสูงสุด (Limit)</div>
        <div class="sub-row">
          <input class="sub-input" type="number" id="feat-limit-voiceabuse" min="1" max="100" value="${feat.limit||5}">
          <span class="sub-unit">ครั้ง</span>
        </div>
      </div>
      <div class="sub-field">
        <div class="sub-label">ช่วงเวลา (Window)</div>
        <div class="sub-row">
          <input class="sub-input" type="number" id="feat-window-voiceabuse" min="1" max="3600" value="${feat.window||10}">
          <span class="sub-unit">วินาที</span>
        </div>
      </div>
      <div class="sub-field">
        <div class="sub-label">⏱ ระยะเวลา Timeout (นาที)</div>
        <div class="sub-row">
          <input class="sub-input" type="number" id="va-mute-dur" min="1" max="43200" value="${feat.mute_duration||10}">
          <span class="sub-unit">นาที</span>
        </div>
      </div>
    </div>
  </div>`;
}

function renderHomeStatus(cfg) {
  // กลุ่ม 1: Anti-Nuke (16 features)
  const NUKE = [
    {key:'anti_ban',          icon:'user-x',     name:'Anti-Ban Member'},
    {key:'anti_kick',         icon:'user-minus',  name:'Anti-Kick Member'},
    {key:'anti_ch_create',    icon:'folder-plus', name:'Anti-Channel Create'},
    {key:'anti_ch_delete',    icon:'folder-minus',name:'Anti-Channel Delete'},
    {key:'anti_ch_update',    icon:'folder-edit', name:'Anti-Channel Update'},
    {key:'anti_role_create',  icon:'tag',         name:'Anti-Role Create'},
    {key:'anti_role_delete',  icon:'x-circle',    name:'Anti-Role Delete'},
    {key:'anti_role_update',  icon:'refresh-cw',  name:'Anti-Role Update'},
    {key:'anti_role_give',    icon:'alert-triangle', name:'Anti-Role Give (Dangerous)'},
    {key:'anti_webhook_create',icon:'webhook',    name:'Anti-Webhook Create'},
    {key:'anti_webhook_delete',icon:'webhook',    name:'Anti-Webhook Delete'},
    {key:'anti_bot_add',      icon:'bot',         name:'Anti-Bot Add'},
    {key:'anti_guild_update', icon:'server',      name:'Anti-Guild Update'},
    {key:'anti_vanity',       icon:'link-2',      name:'Anti-Vanity URL'},
    {key:'anti_prune',        icon:'scissors',    name:'Anti-Prune Members'},
    {key:'anti_integration',  icon:'plug',        name:'Anti-Integration'},
  ];
  // กลุ่ม 2: Anti-Raid (4 features)
  const RAID = [
    {key:'anti_join_flood',  icon:'waves',           name:'Anti-Join Flood'},
    {key:'anti_account_age', icon:'calendar-clock',  name:'Anti-Account Age'},
    {key:'anti_no_avatar',   icon:'user-circle-2',   name:'Anti-Default Avatar'},
    {key:'server_lockdown',  icon:'lock',            name:'Server Lockdown'},
  ];
  // กลุ่ม 3: Anti-Spam (5 features)
  const SPAM = [
    {key:'anti_mass_mentions', icon:'at-sign',   name:'Anti-Mass Mentions'},
    {key:'anti_text_spam',     icon:'repeat-2',  name:'Anti-Text Spam'},
    {key:'anti_link_spam',     icon:'link-2',    name:'Anti-Link & Invite Spam'},
    {key:'anti_att_spam',      icon:'paperclip', name:'Anti-Attachment/Media Spam'},
    {key:'anti_emoji_spam',    icon:'smile',     name:'Anti-Emoji/Reaction Spam'},
  ];
  // Extras
  const EXTRA = [
    {key:'automod',     icon:'bot', name:'Auto Mod'},
    {key:'voiceabuse',  icon:'mic', name:'Voice Abuse'},
  ];

  function countOn(arr) { return arr.filter(s => (cfg[s.key]||{}).enabled).length; }

  // ── Category Summary Cards ──
  const catIcons = {
    nuke: '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>',
    raid: '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>',
    spam: '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>',
    general: '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.07 4.93l-1.41 1.41M4.93 4.93l1.41 1.41M19.07 19.07l-1.41-1.41M4.93 19.07l1.41-1.41M12 2v2M12 20v2M2 12h2M20 12h2"/></svg>',
  };
  const cats = [
    { label:'Anti-Nuke', icon: catIcons.nuke, cls:'nuke', arr:NUKE, page:'antinuke', desc:'ป้องกันผู้ดูแลใช้อำนาจในทางที่ผิด' },
    { label:'Anti-Raid',  icon: catIcons.raid, cls:'raid', arr:RAID, page:'antiraid', desc:'สกัดกั้นการโจมตีพร้อมกัน' },
    { label:'Anti-Spam',  icon: catIcons.spam, cls:'spam', arr:SPAM, page:'antispam', desc:'กรองสแปมข้อความและ Mention' },
    { label:'ทั่วไป',     icon: catIcons.general, cls:'general', arr:EXTRA, page:'automod', desc:'Auto Mod, Voice Abuse และอื่นๆ' },
  ];
  const catWrap = document.getElementById('category-cards');
  if (catWrap) {
    catWrap.innerHTML = cats.map(c => {
      const on = countOn(c.arr);
      const total = c.arr.length;
      const pct = total ? Math.round(on / total * 100) : 0;
      return `<div class="cat-card" onclick="goPage('${c.page}')">
        <div class="cat-card-head">
          <div class="cat-card-ic ${c.cls}">${c.icon}</div>
          <div>
            <div class="cat-card-name">${c.label}</div>
            <div class="cat-card-desc">${c.desc}</div>
          </div>
        </div>
        <div class="cat-card-bar"><div class="cat-card-bar-fill ${c.cls}" style="width:${pct}%"></div></div>
        <div class="cat-card-footer">
          <span>เปิดอยู่ <span class="cat-active-count ${c.cls}">${on}/${total}</span></span>
          <span style="color:var(--primary-light);font-size:11px;">ดูรายละเอียด →</span>
        </div>
      </div>`;
    }).join('');
  }

  // ── Detailed Status List (collapsible by group) ──
  function rows(arr) {
    return arr.map(s => {
      const on = (cfg[s.key]||{}).enabled;
      return `<div class="trow">
        <div class="trow-ic"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-${s.icon}"></svg></div>
        <div class="trow-info"><div class="trow-label">${s.name}</div></div>
        <span class="badge ${on?'badge-green':'badge-gray'}">${on?'เปิด':'ปิด'}</span>
      </div>`;
    }).join('');
  }

  document.getElementById('system-status-list').innerHTML = `
    <div style="font-size:10px;font-weight:700;color:var(--danger);text-transform:uppercase;letter-spacing:.8px;padding:6px 0 4px;display:flex;align-items:center;gap:5px;"><svg xmlns="http://www.w3.org/2000/svg" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg> Anti-Nuke (${countOn(NUKE)}/${NUKE.length} เปิด)</div>
    ${rows(NUKE)}
    <div style="font-size:10px;font-weight:700;color:var(--warn);text-transform:uppercase;letter-spacing:.8px;padding:14px 0 4px;display:flex;align-items:center;gap:5px;"><svg xmlns="http://www.w3.org/2000/svg" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M11 3a1 1 0 1 0 2 0 1 1 0 0 0-2 0"/><path d="M11 21a1 1 0 1 0 2 0 1 1 0 0 0-2 0"/><path d="M3 11a1 1 0 1 0 0 2 1 1 0 0 0 0-2"/><path d="M21 11a1 1 0 1 0 0 2 1 1 0 0 0 0-2"/><circle cx="12" cy="12" r="9"/></svg> Anti-Raid & Gatekeeper (${countOn(RAID)}/${RAID.length} เปิด)</div>
    ${rows(RAID)}
    <div style="font-size:10px;font-weight:700;color:var(--primary-light);text-transform:uppercase;letter-spacing:.8px;padding:14px 0 4px;display:flex;align-items:center;gap:5px;"><svg xmlns="http://www.w3.org/2000/svg" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/><line x1="12" y1="7" x2="12" y2="11"/><line x1="12" y1="15" x2="12.01" y2="15"/></svg> Anti-Spam (${countOn(SPAM)}/${SPAM.length} เปิด)</div>
    ${rows(SPAM)}
    <div style="font-size:10px;font-weight:700;color:var(--success);text-transform:uppercase;letter-spacing:.8px;padding:14px 0 4px;display:flex;align-items:center;gap:5px;"><svg xmlns="http://www.w3.org/2000/svg" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/><circle cx="12" cy="12" r="3"/></svg> ทั่วไป (${countOn(EXTRA)}/${EXTRA.length} เปิด)</div>
    ${rows(EXTRA)}
  `;
  if (window.lucide) lucide.createIcons();
}

// ─── LOG CHANNELS ─────────────────────────────────────────────────
const LOG_CH_TYPES = [
  {key:'member_join',    label:'สมาชิกเข้าร่วม',  icon:'user-plus'},
  {key:'member_leave',   label:'สมาชิกออกจาก',    icon:'user-minus'},
  {key:'member_ban',     label:'แบนสมาชิก',       icon:'ban'},
  {key:'member_kick',    label:'เตะสมาชิก',       icon:'user-x'},
  {key:'message_delete', label:'ลบข้อความ',       icon:'trash-2'},
  {key:'message_edit',   label:'แก้ไขข้อความ',    icon:'pencil'},
  {key:'role_update',    label:'เปลี่ยนยศ',       icon:'tag'},
  {key:'channel_update', label:'เปลี่ยนช่อง',     icon:'hash'},
  {key:'voice_update',   label:'Voice',           icon:'mic'},
  {key:'invite_create',  label:'สร้างลิงก์เชิญ', icon:'link'},
];

function renderLogChannels() {
  const grid = document.getElementById('logch-grid');
  if (!grid) return;
  const LOGCH_ICONS = {
    'user-plus':  '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><line x1="19" y1="8" x2="19" y2="14"/><line x1="22" y1="11" x2="16" y2="11"/></svg>',
    'user-minus': '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><line x1="22" y1="11" x2="16" y2="11"/></svg>',
    'ban':        '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>',
    'user-x':     '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><line x1="17" y1="8" x2="23" y2="14"/><line x1="23" y1="8" x2="17" y2="14"/></svg>',
    'trash-2':    '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>',
    'pencil':     '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M17 3a2.85 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z"/></svg>',
    'tag':        '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2H2v10l9.29 9.29c.94.94 2.48.94 3.42 0l6.58-6.58c.94-.94.94-2.48 0-3.42L12 2Z"/><path d="M7 7h.01"/></svg>',
    'hash':       '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><line x1="4" y1="9" x2="20" y2="9"/><line x1="4" y1="15" x2="20" y2="15"/><line x1="10" y1="3" x2="8" y2="21"/><line x1="16" y1="3" x2="14" y2="21"/></svg>',
    'mic':        '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2a3 3 0 0 0-3 3v7a3 3 0 0 0 6 0V5a3 3 0 0 0-3-3Z"/><path d="M19 10v2a7 7 0 0 1-14 0v-2"/><line x1="12" y1="19" x2="12" y2="22"/></svg>',
    'link':       '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>',
  };
  grid.innerHTML = LOG_CH_TYPES.map(t => {
    const chId = logChConfig[t.key];
    const has = !!chId;
    const iconSvg = LOGCH_ICONS[t.icon] || '';
    return `<div class="logch-card">
      <div class="logch-left">
        <div class="logch-ic">${iconSvg}</div>
        <div>
          <div class="logch-name">${t.label}</div>
          <div class="logch-st ${has?'has':'none'}">${has?`ID: ${chId}`:'ยังไม่มีห้อง'}</div>
        </div>
      </div>
      <div>${has
        ? `<button class="btn btn-danger btn-sm" onclick="deleteLogChannel('${t.key}')">ลบ</button>`
        : `<button class="btn btn-success btn-sm" onclick="createLogChannel('${t.key}')">+ สร้าง</button>`
      }</div>
    </div>`;
  }).join('');
  if (window.lucide) lucide.createIcons();
}

async function createLogChannel(logType) {
  try {
    const r = await fetch(`${API_BASE}/api/log-channels/create?token=${encodeURIComponent(getToken())}`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({log_type: logType})
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error);
    logChConfig[logType] = d.channel_id;
    renderLogChannels();
    toast(`สร้างห้อง ${d.channel_name} แล้ว`, 'success');
  } catch(e) { toast(`เกิดข้อผิดพลาด: ${e.message}`, 'error'); }
}

async function deleteLogChannel(logType) {
  try {
    await fetch(`${API_BASE}/api/log-channels/delete?token=${encodeURIComponent(getToken())}`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({log_type: logType})
    });
    logChConfig[logType] = null;
    renderLogChannels();
    toast('ลบการเชื่อม log แล้ว', 'success');
  } catch { toast('เกิดข้อผิดพลาด', 'error'); }
}

async function autoCreateLogs() {
  for (const t of LOG_CH_TYPES) {
    if (!logChConfig[t.key]) {
      await createLogChannel(t.key);
      await new Promise(r => setTimeout(r, 600));
    }
  }
}

// ─── LOAD / SAVE CONFIG ───────────────────────────────────────────
async function loadConfig() {
  try {
    const r = await fetch(`${API_BASE}/api/config?token=${encodeURIComponent(getToken())}`);
    if (!r.ok) throw new Error('unauthorized');
    CFG = await r.json();

    // Populate feature pages
    renderAllPages(CFG);
    renderHomeStatus(CFG);

    // AutoMod
    const am = CFG.automod || {};
    setCheck('am-enabled', am.enabled);
    setCheck('am-links',   am.filter_links);
    setCheck('am-invites', am.filter_invites);
    setCheck('am-caps',    am.filter_caps);
    setVal('am-mute-dur',  am.mute_duration || 5);
    buildPunishWrap('pun-automod', am.punishment || 'timeout');
    savedWords = [...(am.banned_words || [])];
    renderChips();

    // Welcome
    const wlc = CFG.welcome || {};
    setCheck('wlc-en', wlc.enabled);
    setVal('wlc-ch',  wlc.channel_id || '');
    setVal('wlc-msg', wlc.message || '');

    // Whitelist
    const wl = CFG.whitelist || {};
    wlUserIds  = (wl.users||[]).map(String);
    wlRoleIds  = (wl.roles||[]).map(String);
    setVal('wl-bots',  ((CFG.anti_bot_add||{}).bot_whitelist||[]).join('\n'));
    await loadWlRoles();
    renderWlRoleChips();
    renderWlUserChips();

    // Settings
    setVal('bl-role-id', CFG.blacklist_role_id || '');

    // Main log channel
    setVal('main-log-ch', CFG.log_channel_id || '');

    // Log channels
    logChConfig = {...(CFG.log_channels || {})};
    renderLogChannels();
    // Update protection donut chart
    updateCharts(CFG, null);

    // โหลดสถานะ advanced_mode กลับใส่ checkbox
    const advModes = CFG.advanced_mode || {};
    const ADV_KEYS = [
      'anti_ban','anti_kick','anti_ch_create','anti_ch_delete','anti_ch_update',
      'anti_role_create','anti_role_delete','anti_role_update','anti_role_give',
      'anti_webhook_create','anti_webhook_delete','anti_bot_add','anti_guild_update',
      'anti_vanity','anti_prune','anti_integration',
      'anti_join_flood',
      'anti_mass_mentions','anti_text_spam','anti_link_spam','anti_att_spam','anti_emoji_spam',
    ];
    for (const key of ADV_KEYS) {
      const cb = document.getElementById('adv-en-' + key);
      if (cb) cb.checked = !!advModes[key];
    }

  } catch(e) {
    toast('โหลด config ไม่ได้: ' + e.message, 'error');
  }
}

async function saveConfig() {
  const payload = {};

  // Collect all standard feature values (toggle + limit + window + punishment)
  const FEAT_KEYS = [
    'anti_ban','anti_kick','anti_ch_create','anti_ch_delete','anti_ch_update',
    'anti_role_create','anti_role_delete','anti_role_update','anti_role_give',
    'anti_webhook_create','anti_webhook_delete','anti_bot_add','anti_guild_update',
    'anti_vanity','anti_prune','anti_integration',
    'anti_join_flood',
    'anti_mass_mentions','anti_text_spam','anti_link_spam','anti_att_spam','anti_emoji_spam',
  ];
  const advModePayload = {};
  for (const key of FEAT_KEYS) {
    const enEl = document.getElementById('feat-en-' + key);
    if (enEl) {
      const val = getFeatVal(key);
      // แยก _adv_mode ออกก่อนส่ง config ปกติ
      const { _adv_mode, ...featVal } = val;
      payload[key] = featVal;
      advModePayload[key] = _adv_mode;
    }
  }
  payload['advanced_mode'] = advModePayload;

  // Anti-Account Age — limit = min days, no window
  const aaEl = document.getElementById('feat-en-anti_account_age');
  if (aaEl) {
    payload['anti_account_age'] = {
      enabled:    aaEl.checked,
      limit:      parseInt(document.getElementById('feat-limit-anti_account_age')?.value) || 7,
      punishment: document.getElementById('punish-anti_account_age')?.dataset.val || 'kick',
    };
  }

  // Anti-No Avatar — toggle + punishment only
  const naEl = document.getElementById('feat-en-anti_no_avatar');
  if (naEl) {
    payload['anti_no_avatar'] = {
      enabled:    naEl.checked,
      punishment: document.getElementById('punish-anti_no_avatar')?.dataset.val || 'kick',
    };
  }

  // Lockdown
  const ldEl = document.getElementById('feat-en-server_lockdown');
  if (ldEl) payload['server_lockdown'] = {enabled: ldEl.checked};

  // Voice abuse
  const vaEn    = document.getElementById('feat-en-voiceabuse');
  const vaLimit = document.getElementById('feat-limit-voiceabuse');
  const vaWin   = document.getElementById('feat-window-voiceabuse');
  const vaMute  = document.getElementById('va-mute-dur');
  const vaPun   = document.getElementById('punish-voiceabuse');
  if (vaEn) payload['voiceabuse'] = {
    enabled:       vaEn.checked,
    limit:         parseInt(vaLimit?.value)||5,
    window:        parseInt(vaWin?.value)||10,
    punishment:    vaPun?.dataset.val || 'timeout',
    mute_duration: parseInt(vaMute?.value)||10,
  };

  // AutoMod
  const amPun = document.getElementById('pun-automod');
  payload['automod'] = {
    enabled:        getCheck('am-enabled'),
    filter_links:   getCheck('am-links'),
    filter_invites: getCheck('am-invites'),
    filter_caps:    getCheck('am-caps'),
    punishment:     amPun ? (amPun.dataset.val || 'timeout') : 'timeout',
    mute_duration:  parseInt(getVal('am-mute-dur')) || 5,
    banned_words:   savedWords,
  };

  // Welcome
  payload['welcome'] = {
    enabled:    getCheck('wlc-en'),
    channel_id: getVal('wlc-ch') || null,
    message:    getVal('wlc-msg'),
  };

  // Whitelist
  payload['whitelist'] = {
    users: wlUserIds,
    roles: wlRoleIds,
  };

  // Bot whitelist (inside anti_bot_add — merge ไม่ overwrite)
  if (payload['anti_bot_add']) {
    payload['anti_bot_add'].bot_whitelist = getVal('wl-bots')
      .split('\n').map(s => s.trim()).filter(Boolean);
  } else {
    // anti_bot_add อาจไม่ได้อยู่ใน FEAT_KEYS render แล้ว ต้อง set แยก
    const abEl = document.getElementById('feat-en-anti_bot_add');
    if (abEl) {
      payload['anti_bot_add'] = {
        ...getFeatVal('anti_bot_add'),
        bot_whitelist: getVal('wl-bots').split('\n').map(s=>s.trim()).filter(Boolean),
      };
    }
  }

  // Settings
  payload['blacklist_role_id'] = getVal('bl-role-id') || null;
  payload['log_channel_id']    = getVal('main-log-ch') || null;

  try {
    const r = await fetch(`${API_BASE}/api/config?token=${encodeURIComponent(getToken())}`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify(payload)
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error);
    CFG = {...CFG, ...payload};
    renderHomeStatus(CFG);
    toast('บันทึกเรียบร้อยแล้ว', 'success');
  } catch(e) {
    toast('บันทึกไม่ได้: ' + e.message, 'error');
  }
}

// ─── STATS ────────────────────────────────────────────────────────
async function loadStats() {
  try {
    const r = await fetch(`${API_BASE}/api/stats?token=${encodeURIComponent(getToken())}`);
    if (!r.ok) return;
    const d = await r.json();
    // Banner
    document.getElementById('ban-name').textContent    = d.guild_name || '-';
    document.getElementById('ban-members').textContent = `${d.member_count} สมาชิก • ${d.online_count} ออนไลน์`;
    const banIcon = document.getElementById('ban-icon');
    if (d.icon_url) banIcon.innerHTML = `<img src="${d.icon_url}" alt="icon"/>`;
    // Sidebar
    document.getElementById('sb-sname').textContent = d.guild_name || '-';
    document.getElementById('sb-sid').textContent   = d.server_id  || '-';
    const sbIw = document.getElementById('sb-icon-wrap');
    if (d.icon_url) sbIw.innerHTML = `<img src="${d.icon_url}" alt="icon"/>`;
    // Stats
    setHtml('st-members',  d.member_count);
    setHtml('st-online',   d.online_count);
    setHtml('st-channels', d.channel_count);
    setHtml('st-roles',    d.role_count);
    document.querySelectorAll('.stat-num.skeleton').forEach(e => e.classList.remove('skeleton'));
    // Lockdown banner
    const ldBanner = document.getElementById('ld-banner');
    if (ldBanner) ldBanner.classList.toggle('hidden', !d.in_lockdown);
    // Update server chart
    updateCharts(CFG, d);
  } catch(e) { log.error && console.error(e); }
}

// ─── LOCKDOWN ─────────────────────────────────────────────────────
async function toggleLockdown(enable) {
  try {
    const r = await fetch(`${API_BASE}/api/lockdown?token=${encodeURIComponent(getToken())}`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({enable})
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error);
    const ldBanner = document.getElementById('ld-banner');
    if (ldBanner) ldBanner.classList.toggle('hidden', !enable);
    const ldEl = document.getElementById('feat-en-server_lockdown');
    if (ldEl) ldEl.checked = enable;
    toggleFeatCard('server_lockdown', enable);
    toast(enable ? 'Lockdown เปิดแล้ว' : 'Lockdown ปิดแล้ว', enable?'error':'success');
  } catch(e) { toast(e.message, 'error'); }
}

// ─── LOGS ─────────────────────────────────────────────────────────
const LOG_COLORS = {
  ban:'#ff4757', kick:'#ffa502', message_delete:'#d29922',
  channel_delete:'#ff4757', role_delete:'#ff4757',
  member_update:'#3b6ef8', member_ban:'#ff4757', member_kick:'#ffa502',
};

async function loadLogs() {
  const list = document.getElementById('log-list');
  list.innerHTML = '<div style="padding:24px;text-align:center;color:var(--muted);"><div class="loader" style="margin:auto;"></div></div>';
  try {
    const r = await fetch(`${API_BASE}/api/logs?token=${encodeURIComponent(getToken())}`);
    if (!r.ok) throw new Error();
    const logs = await r.json();
    if (!logs.length) { list.innerHTML='<div style="padding:24px;text-align:center;color:var(--muted);">ไม่มีบันทึก</div>'; return; }
    list.innerHTML = logs.map(l => {
      const action = (l.action||'').replace(/_/g,' ');
      const color  = LOG_COLORS[(l.action||'').toLowerCase()] || '#3d5478';
      const dt = l.timestamp ? new Date(l.timestamp).toLocaleString('th-TH',{hour:'2-digit',minute:'2-digit',day:'numeric',month:'short'}) : '';
      return `<div class="log-item">
        <span class="log-badge" style="background:${color}22;color:${color};">${action}</span>
        <div class="log-body">
          <div class="log-action">${escHtml(l.user||'-')}</div>
          <div class="log-meta">เป้าหมาย: ${escHtml(String(l.target||'-'))}${l.reason&&l.reason!=='-'?' • '+escHtml(l.reason):''}</div>
        </div>
        <div class="log-time">${dt}</div>
      </div>`;
    }).join('');
  } catch {
    list.innerHTML='<div style="padding:24px;text-align:center;color:var(--muted);">โหลดบันทึกไม่ได้</div>';
  }
}

// ─── CHIPS (Banned Words) ─────────────────────────────────────────
function renderChips() {
  const wrap = document.getElementById('bw-chips');
  if (!wrap) return;
  wrap.innerHTML = savedWords.map((w,i) =>
    `<div class="chip">${escHtml(w)}<button onclick="removeWord(${i})">×</button></div>`
  ).join('');
}
function removeWord(i) { savedWords.splice(i,1); renderChips(); }
document.addEventListener('keydown', e => {
  const inp = document.getElementById('bw-inp');
  if (e.key === 'Enter' && document.activeElement === inp) {
    const val = inp.value.trim();
    if (val && !savedWords.includes(val)) { savedWords.push(val); renderChips(); }
    inp.value = '';
  }
});

// ─── PAGE NAVIGATION ──────────────────────────────────────────────
const PAGE_TITLES = {
  home:          ['หน้าหลัก',           'ภาพรวมและสถานะของ Server'],
  antinuke:      ['Anti-Nuke',           'ป้องกันการทำลายเซิร์ฟเวอร์'],
  antiraid:      ['Anti-Raid',           'สกัดกั้นการโจมตีและบัญชีอวตาร'],
  lockdown:      ['Server Lockdown',     'ล็อกทุกช่องทางในกรณีฉุกเฉิน'],
  antispam:      ['Anti-Spam',           'รักษาความสงบในช่องแชท'],
  automod:       ['Auto Mod',            'กรองข้อความอัตโนมัติ'],
  voiceabuse:    ['Voice Abuse',         'ป้องกันการใช้ Voice ในทางที่ผิด'],
  welcome:       ['Welcome',             'ข้อความต้อนรับสมาชิกใหม่'],
  whitelist:     ['Whitelist',            'ข้ามการตรวจสอบทั้งหมด'],
  memberprofile: ['โปรไฟล์สมาชิก',       'ดูโปรไฟล์และตั้งค่าการยกเว้นรายบุคคล'],
  suspicious:    ['พฤติกรรมน่าสงสัย',     'แจ้งเตือนพฤติกรรมผิดปกติในเซิร์ฟเวอร์'],
  roleinspector: ['Role Inspector',      'ดูสิทธิ์ห้องของแต่ละยศ'],
  logchannels:   ['Log Channels',        'ห้อง Log อัตโนมัติ'],
  settings:      ['ตั้งค่าทั่วไป',      'การตั้งค่าหลักของบอท'],
  logs:          ['Audit Log',           'ประวัติการกระทำใน Server'],
};

function goPage(id) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item,.bnav-item').forEach(n => n.classList.remove('active'));
  const page = document.getElementById('page-' + id);
  if (page) page.classList.add('active');
  const info = PAGE_TITLES[id] || [id,''];
  document.getElementById('page-title').textContent = info[0];
  document.getElementById('page-sub').textContent   = info[1];
  document.querySelectorAll('.nav-item,.bnav-item').forEach(n => {
    if (n.getAttribute('onclick') === `goPage('${id}')`) n.classList.add('active');
  });
  if (window.lucide) lucide.createIcons();
  if (id === 'logs')          loadLogs();
  if (id === 'roleinspector') loadRoleInspector();
  if (id === 'suspicious')    loadSuspiciousAlerts();
  if (id === 'memberprofile') mpRenderRecent();
}

// ─── INIT BL (call !initbl equivalent via bot) ────────────────────
// Since !initbl is a Discord command, we guide the user
function sendInitBl() {
  toast('พิมพ์ !initbl ใน Discord แล้วบอทจะสร้างยศ Blacklist ให้อัตโนมัติ', 'success', 5000);
}

// ─── AUTH ─────────────────────────────────────────────────────────
async function doLogin() {
  const t = document.getElementById('token-inp').value.trim();
  if (!t) return;
  try {
    const r = await fetch(`${API_BASE}/api/verify?token=${encodeURIComponent(t)}`);
    const d = await r.json();
    if (!d.valid) { document.getElementById('login-err').classList.add('show'); return; }
    setToken(t);
    showApp();
  } catch { document.getElementById('login-err').classList.add('show'); }
}

function showApp() {
  document.getElementById('login-view').classList.add('hidden');
  document.getElementById('app-view').classList.add('active');
  if (window.lucide) lucide.createIcons();
  setTimeout(initCharts, 100);
  loadConfig();
  loadStats();
  // Refresh stats every 30 seconds
  setInterval(loadStats, 30000);
}

function doLogout() {
  sessionStorage.removeItem('sb_token');
  location.reload();
}

document.getElementById('token-inp').addEventListener('keydown', e => {
  if (e.key === 'Enter') doLogin();
});

// ─── UTILS ────────────────────────────────────────────────────────
function escHtml(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function setCheck(id, v) { const el = document.getElementById(id); if (el) el.checked = !!v; }
function getCheck(id) { const el = document.getElementById(id); return el ? el.checked : false; }
function setVal(id, v) { const el = document.getElementById(id); if (el) el.value = v ?? ''; }
function getVal(id) { const el = document.getElementById(id); return el ? el.value : ''; }
function setHtml(id, v) { const el = document.getElementById(id); if (el) el.textContent = v; }

function toast(msg, type='success', dur=3500) {
  const wrap = document.getElementById('toast-wrap');
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.textContent = msg;
  wrap.appendChild(el);
  setTimeout(() => { el.classList.add('fade-out'); setTimeout(()=>el.remove(), 300); }, dur);
}

// ─── WHITELIST ROLE + MEMBER ──────────────────────────────────────
let wlSearchTimer = null;

async function loadWlRoles() {
  try {
    const r = await fetch(`${API_BASE}/api/roles?token=${encodeURIComponent(getToken())}`);
    if (!r.ok) return;
    wlRoleData = await r.json();
    const sel = document.getElementById('wl-role-select');
    if (!sel) return;
    sel.innerHTML = '<option value="">— เลือกยศ —</option>' +
      wlRoleData.map(ro =>
        `<option value="${ro.id}">${escHtml(ro.name)}</option>`
      ).join('');
  } catch(e) { console.error('loadWlRoles', e); }
}

function renderWlRoleChips() {
  const wrap = document.getElementById('wl-role-chips');
  if (!wrap) return;
  wrap.innerHTML = wlRoleIds.map(id => {
    const ro = wlRoleData.find(r => r.id === id);
    const name = ro ? ro.name : id;
    return `<div class="chip"><svg xmlns="http://www.w3.org/2000/svg" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="margin-right:3px;"><path d="M12 2H2v10l9.29 9.29c.94.94 2.48.94 3.42 0l6.58-6.58c.94-.94.94-2.48 0-3.42L12 2Z"/><path d="M7 7h.01"/></svg> ${escHtml(name)}<button onclick="wlRemoveRole('${id}')">×</button></div>`;
  }).join('');
  if (window.lucide) lucide.createIcons();
}

function renderWlUserChips() {
  const wrap = document.getElementById('wl-user-chips');
  if (!wrap) return;
  wrap.innerHTML = wlUserIds.map(id => {
    const u = wlUserData[id];
    const name = u ? (u.display_name || u.name) : id;
    return `<div class="chip"><svg xmlns="http://www.w3.org/2000/svg" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="margin-right:3px;"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg> ${escHtml(name)}<button onclick="wlRemoveUser('${id}')">×</button></div>`;
  }).join('');
  if (window.lucide) lucide.createIcons();
}

function wlAddRole() {
  const sel = document.getElementById('wl-role-select');
  if (!sel || !sel.value) return;
  if (!wlRoleIds.includes(sel.value)) {
    wlRoleIds.push(sel.value);
    renderWlRoleChips();
  }
  sel.value = '';
}

function wlRemoveRole(id) {
  wlRoleIds = wlRoleIds.filter(r => r !== id);
  renderWlRoleChips();
}

function wlRemoveUser(id) {
  wlUserIds = wlUserIds.filter(u => u !== id);
  renderWlUserChips();
}

function wlSearchMembers(q) {
  clearTimeout(wlSearchTimer);
  const dd = document.getElementById('wl-member-dropdown');
  if (!q.trim()) { dd.style.display = 'none'; return; }
  wlSearchTimer = setTimeout(async () => {
    try {
      const r = await fetch(`${API_BASE}/api/members?token=${encodeURIComponent(getToken())}&q=${encodeURIComponent(q)}`);
      if (!r.ok) return;
      const members = await r.json();
      if (!members.length) {
        dd.style.display = 'none'; return;
      }
      dd.innerHTML = members.map(m => `
        <div onclick="wlSelectMember('${m.id}')"
             style="display:flex;align-items:center;gap:10px;padding:9px 13px;cursor:pointer;
                    border-bottom:1px solid var(--border);transition:background .12s;"
             onmouseover="this.style.background='var(--surface3)'"
             onmouseout="this.style.background=''">
          <img src="${escHtml(m.avatar)}" alt="" style="width:30px;height:30px;border-radius:50%;flex-shrink:0;"/>
          <div>
            <div style="font-size:13px;font-weight:600;color:var(--text);">${escHtml(m.display_name)}</div>
            <div style="font-size:11px;color:var(--muted);">${escHtml(m.name)} • ${m.id}</div>
          </div>
        </div>`).join('');
      dd.style.display = 'block';
    } catch(e) { console.error('wlSearch', e); }
  }, 250);
}

function wlSelectMember(id) {
  const member = (document.getElementById('wl-member-dropdown').querySelectorAll('[onclick]'));
  // Store member data from dropdown items already rendered
  fetch(`${API_BASE}/api/members?token=${encodeURIComponent(getToken())}&q=${id}`)
    .then(r => r.json()).then(members => {
      const m = members.find(x => x.id === id);
      if (m) wlUserData[id] = m;
      if (!wlUserIds.includes(id)) {
        wlUserIds.push(id);
        renderWlUserChips();
      }
    });
  document.getElementById('wl-member-search').value = '';
  document.getElementById('wl-member-dropdown').style.display = 'none';
}

// Close member dropdown when clicking outside
document.addEventListener('click', e => {
  const dd = document.getElementById('wl-member-dropdown');
  const inp = document.getElementById('wl-member-search');
  if (dd && inp && !dd.contains(e.target) && e.target !== inp) {
    dd.style.display = 'none';
  }
});

// ─── MEMBER PROFILE ───────────────────────────────────────────────
let mpSearchTimer = null;
let mpCurrentMemberId = null;
let mpRecentMembers = JSON.parse(localStorage.getItem('mpRecent') || '[]');

function mpSaveRecent(m) {
  mpRecentMembers = mpRecentMembers.filter(r => r.id !== m.id);
  mpRecentMembers.unshift(m);
  if (mpRecentMembers.length > 20) mpRecentMembers = mpRecentMembers.slice(0, 20);
  try { localStorage.setItem('mpRecent', JSON.stringify(mpRecentMembers)); } catch(e) {}
}

function mpRenderRecent() {
  const list = document.getElementById('mp-recent-list');
  if (!list) return;
  if (!mpRecentMembers.length) {
    list.innerHTML = '<div style="color:var(--muted);font-size:13px;text-align:center;padding:18px 0;">ยังไม่มีประวัติการดู — ค้นหาและเลือกสมาชิกด้านบน</div>';
    return;
  }
  list.innerHTML = mpRecentMembers.map(m => `
    <div style="display:flex;align-items:center;gap:12px;padding:10px 12px;
                background:var(--surface2);border-radius:10px;margin-bottom:6px;
                cursor:pointer;border:1px solid var(--border);transition:all .15s;"
         onclick="mpSelectMember('${m.id}')"
         onmouseover="this.style.borderColor='var(--border2)'"
         onmouseout="this.style.borderColor='var(--border)'">
      <img src="${escHtml(m.avatar||'')}" alt="" onerror="this.style.display='none'"
           style="width:38px;height:38px;border-radius:50%;border:1.5px solid var(--border2);flex-shrink:0;"/>
      <div style="flex:1;min-width:0;">
        <div style="font-size:13px;font-weight:700;color:var(--text);">${escHtml(m.display_name||m.name)}</div>
        <div style="font-size:11px;color:var(--muted);">${escHtml(m.name)} • ${m.id}</div>
      </div>
      <button onclick="event.stopPropagation();mpShowSettingsFor('${m.id}')"
              title="ดูการตั้งค่าการยกเว้น"
              style="background:var(--surface3);border:1px solid var(--border);border-radius:7px;
                     padding:6px 9px;font-size:15px;cursor:pointer;color:var(--muted);
                     transition:all .15s;flex-shrink:0;"
              onmouseover="this.style.color='var(--text)'"
              onmouseout="this.style.color='var(--muted)'"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/><circle cx="12" cy="12" r="3"/></svg></button>
    </div>`).join('');
  if (window.lucide) lucide.createIcons();
}

async function mpShowSettingsFor(id) {
  await mpSelectMember(id);
  document.getElementById('mp-settings-panel').style.display = 'block';
}

function mpToggleSettings() {
  const p = document.getElementById('mp-settings-panel');
  p.style.display = p.style.display === 'none' ? 'block' : 'none';
}

function mpSearch(q) {
  clearTimeout(mpSearchTimer);
  const dd = document.getElementById('mp-dropdown');
  if (!q.trim()) { dd.style.display = 'none'; return; }
  mpSearchTimer = setTimeout(async () => {
    try {
      const r = await fetch(`${API_BASE}/api/members?token=${encodeURIComponent(getToken())}&q=${encodeURIComponent(q)}`);
      if (!r.ok) return;
      const members = await r.json();
      if (!members.length) { dd.style.display = 'none'; return; }
      dd.innerHTML = members.map(m => `
        <div onclick="mpSelectMember('${m.id}')"
             style="display:flex;align-items:center;gap:10px;padding:9px 13px;cursor:pointer;
                    border-bottom:1px solid var(--border);transition:background .12s;"
             onmouseover="this.style.background='var(--surface3)'"
             onmouseout="this.style.background=''">
          <img src="${escHtml(m.avatar)}" alt="" style="width:30px;height:30px;border-radius:50%;flex-shrink:0;"/>
          <div>
            <div style="font-size:13px;font-weight:600;color:var(--text);">${escHtml(m.display_name)}</div>
            <div style="font-size:11px;color:var(--muted);">${escHtml(m.name)} • ${m.id}</div>
          </div>
        </div>`).join('');
      dd.style.display = 'block';
    } catch(e) { console.error('mpSearch', e); }
  }, 250);
}

async function mpSelectMember(id) {
  document.getElementById('mp-dropdown').style.display = 'none';
  document.getElementById('mp-search').value = '';
  mpCurrentMemberId = id;
  document.getElementById('mp-settings-panel').style.display = 'none';
  try {
    const r = await fetch(`${API_BASE}/api/member-detail?token=${encodeURIComponent(getToken())}&member_id=${id}`);
    if (!r.ok) { toast('ไม่พบสมาชิก','error'); return; }
    const m = await r.json();

    // Save to recent
    mpSaveRecent({ id: m.id, name: m.name, display_name: m.display_name, avatar: m.avatar });
    mpRenderRecent();

    document.getElementById('mp-avatar').src = m.avatar;
    document.getElementById('mp-name').textContent = m.display_name + (m.is_owner ? ' ★' : '');
    document.getElementById('mp-username').textContent = m.name;
    document.getElementById('mp-id').textContent = 'ID: ' + m.id;
    document.getElementById('mp-joined').textContent = m.joined_at ? new Date(m.joined_at).toLocaleDateString('th-TH') : '—';
    document.getElementById('mp-created').textContent = new Date(m.created_at).toLocaleDateString('th-TH');

    const rolesEl = document.getElementById('mp-roles');
    rolesEl.innerHTML = m.roles.length
      ? m.roles.map(ro => {
          const c = ro.color !== '#000000' ? ro.color : 'var(--border2)';
          return `<div class="chip" style="border-color:${c};"><svg xmlns="http://www.w3.org/2000/svg" width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="margin-right:3px;"><path d="M12 2H2v10l9.29 9.29c.94.94 2.48.94 3.42 0l6.58-6.58c.94-.94.94-2.48 0-3.42L12 2Z"/><path d="M7 7h.01"/></svg>${escHtml(ro.name)}</div>`;
        }).join('')
      : '<span style="color:var(--muted);font-size:12px;">ไม่มียศพิเศษ</span>';
    if (window.lucide) lucide.createIcons();

    // Load exemptions
    const ex = m.exemptions || {};
    setCheck('ex-all',     ex.all     || false);
    setCheck('ex-spam',    ex.spam    || false);
    setCheck('ex-links',   ex.links   || false);
    setCheck('ex-mentions',ex.mentions|| false);
    setCheck('ex-raid',    ex.raid    || false);
    setCheck('ex-nuke',    ex.nuke    || false);
    setCheck('ex-automod', ex.automod || false);
    setCheck('ex-voice',   ex.voice   || false);

    document.getElementById('mp-panel').style.display = 'block';
    document.getElementById('mp-panel').scrollIntoView({behavior:'smooth', block:'start'});

    // Load suspicious actions for this member
    loadMemberSuspicious(id);
  } catch(e) { toast('เกิดข้อผิดพลาด','error'); }
}

async function loadMemberSuspicious(memberId) {
  const panel = document.getElementById('mp-suspicious-list');
  if (!panel) return;
  try {
    const r = await fetch(`${API_BASE}/api/member-actions?token=${encodeURIComponent(getToken())}&member_id=${memberId}`);
    if (!r.ok) { panel.innerHTML = '<div style="color:var(--muted);font-size:13px;text-align:center;padding:12px;">ไม่มีข้อมูล</div>'; return; }
    const actions = await r.json();
    if (!actions.length) {
      panel.innerHTML = '<div style="color:var(--success);font-size:13px;text-align:center;padding:12px;">ไม่พบการกระทำน่าสงสัย</div>';
      return;
    }
    // Group by key
    const grouped = {};
    actions.forEach(a => { if (!grouped[a.key]) grouped[a.key] = 0; grouped[a.key]++; });
    panel.innerHTML = Object.entries(grouped).map(([k,cnt]) => `
      <div style="display:flex;justify-content:space-between;align-items:center;
                  padding:8px 12px;background:var(--surface2);border-radius:8px;margin-bottom:6px;">
        <span style="font-size:13px;color:var(--text);">${k}</span>
        <span style="font-size:12px;font-weight:700;color:var(--accent);">${cnt} ครั้ง</span>
      </div>`).join('') +
      `<div style="font-size:11px;color:var(--muted);text-align:right;margin-top:4px;">(${actions.length} รายการล่าสุด)</div>`;
  } catch(e) {
    panel.innerHTML = '<div style="color:var(--muted);font-size:13px;text-align:center;padding:12px;">โหลดไม่ได้</div>';
  }
}

function exToggleAll(cb) {
  ['ex-spam','ex-links','ex-mentions','ex-raid','ex-nuke','ex-automod','ex-voice']
    .forEach(id => setCheck(id, cb.checked));
}

async function mpSaveExemptions() {
  if (!mpCurrentMemberId) return;
  const exemptions = {
    all:      getCheck('ex-all'),
    spam:     getCheck('ex-spam'),
    links:    getCheck('ex-links'),
    mentions: getCheck('ex-mentions'),
    raid:     getCheck('ex-raid'),
    nuke:     getCheck('ex-nuke'),
    automod:  getCheck('ex-automod'),
    voice:    getCheck('ex-voice'),
  };
  try {
    const r = await fetch(`${API_BASE}/api/member-exemptions?token=${encodeURIComponent(getToken())}`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({member_id: mpCurrentMemberId, exemptions})
    });
    if (!r.ok) throw new Error();
    toast('บันทึกการตั้งค่าแล้ว');
  } catch(e) { toast('เกิดข้อผิดพลาด','error'); }
}

function mpClearExemptions() {
  ['ex-all','ex-spam','ex-links','ex-mentions','ex-raid','ex-nuke','ex-automod','ex-voice']
    .forEach(id => setCheck(id, false));
}

document.addEventListener('click', e => {
  const dd = document.getElementById('mp-dropdown');
  const inp = document.getElementById('mp-search');
  if (dd && inp && !dd.contains(e.target) && e.target !== inp) dd.style.display = 'none';
});

// ─── SUSPICIOUS ALERTS ────────────────────────────────────────────
let susAllAlerts = [];
let susCurrentFilter = 'all';

async function loadSuspiciousAlerts() {
  const list = document.getElementById('sus-alert-list');
  if (!list) return;
  list.innerHTML = '<div style="color:var(--muted);font-size:13px;text-align:center;padding:30px 0;">⏳ กำลังโหลด...</div>';
  try {
    const r = await fetch(`${API_BASE}/api/suspicious-alerts?token=${encodeURIComponent(getToken())}`);
    if (!r.ok) return;
    susAllAlerts = await r.json();
    susCurrentFilter = 'all';
    susRenderAlerts();
  } catch(e) {
    list.innerHTML = '<div style="color:var(--danger);text-align:center;padding:20px;">โหลดไม่ได้</div>';
  }
}

function susRenderAlerts() {
  const list = document.getElementById('sus-alert-list');
  const SEV_COLOR = { high: '#ff4757', medium: '#ffa502', low: '#2ed573' };
  const SEV_LABEL = { high: 'สูง', medium: 'กลาง', low: 'ต่ำ' };
  const filtered = susAllAlerts.filter(a => {
    if (susCurrentFilter === 'high')   return a.severity === 'high';
    if (susCurrentFilter === 'med')    return a.severity === 'medium';
    if (susCurrentFilter === 'low')    return a.severity === 'low';
    return true;
  });
  if (!filtered.length) {
    list.innerHTML = '<div style="color:var(--success);font-size:14px;text-align:center;padding:40px 0;">ไม่พบพฤติกรรมน่าสงสัย</div>';
    susUpdateFilterBtns();
    return;
  }
  list.innerHTML = filtered.map(a => {
    const color = SEV_COLOR[a.severity] || '#ccc';
    const label = SEV_LABEL[a.severity] || a.severity;
    const timeStr = new Date(a.ts * 1000).toLocaleString('th-TH');
    return `<div style="background:var(--surface);border:1.5px solid ${color}30;border-left:4px solid ${color};
                        border-radius:10px;padding:14px;${a.read ? 'opacity:.65;' : ''}">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">
        ${a.member_avatar ? `<img src="${escHtml(a.member_avatar)}" alt=""
             style="width:36px;height:36px;border-radius:50%;border:1.5px solid ${color};flex-shrink:0;"/>` : ''}
        <div style="flex:1;min-width:0;">
          <div style="font-size:14px;font-weight:700;color:#fff;">${escHtml(a.member_name)}</div>
          <div style="font-size:11px;color:var(--muted);">${timeStr}</div>
        </div>
        <span style="background:${color}22;color:${color};border:1px solid ${color}44;
                     border-radius:6px;padding:3px 10px;font-size:11px;font-weight:700;">${label}</span>
      </div>
      <div style="font-size:13px;color:var(--text);margin-bottom:6px;">${escHtml(a.desc)}</div>
      <div style="font-size:12px;color:var(--muted);">
        เกิดขึ้น <strong style="color:${color};">${a.count} ครั้ง</strong> ในช่วง ${a.window} วินาที
        ${a.detail ? `— ${escHtml(a.detail)}` : ''}
      </div>
      <div style="margin-top:10px;display:flex;gap:8px;">
        <button class="btn btn-sm" onclick="mpSelectMember('${a.user_id}');goPage('memberprofile')"
                style="flex:1;">ดูโปรไฟล์</button>
        ${!a.read ? `<button class="btn btn-sm" onclick="susMarkRead('${a.id}',this)"
                style="color:var(--muted);">รับทราบ</button>` : ''}
      </div>
    </div>`;
  }).join('');
  susUpdateFilterBtns();
}

function susUpdateFilterBtns() {
  ['all','high','med','low'].forEach(f => {
    const btn = document.getElementById(`sus-filter-${f}`);
    if (btn) btn.style.background = f === susCurrentFilter ? 'var(--primary-glow)' : '';
  });
}

function susFilter(f) { susCurrentFilter = f; susRenderAlerts(); }

async function susMarkRead(alertId, btn) {
  try {
    await fetch(`${API_BASE}/api/suspicious-alerts/read?token=${encodeURIComponent(getToken())}`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({id: alertId})
    });
    const a = susAllAlerts.find(x => x.id === alertId);
    if (a) a.read = true;
    susRenderAlerts();
  } catch(e) { toast('เกิดข้อผิดพลาด','error'); }
}

// ─── ROLE INSPECTOR ───────────────────────────────────────────────
let riAllChannels = [];
let riCurrentFilter = 'all';
let riRoleMap = {};  // id -> {name, color}

async function loadRoleInspector() {
  const list = document.getElementById('ri-role-list');
  if (!list) return;
  list.innerHTML = '<div style="color:var(--muted);font-size:13px;">⏳ กำลังโหลดยศ...</div>';
  try {
    const r = await fetch(`${API_BASE}/api/roles?token=${encodeURIComponent(getToken())}`);
    if (!r.ok) return;
    const roles = await r.json();
    riRoleMap = {};
    list.innerHTML = roles.map(ro => {
      const colorHex = (ro.color && ro.color !== '#000000' && ro.color !== '0x000000')
        ? (ro.color.startsWith('#') ? ro.color : '#' + parseInt(ro.color).toString(16).padStart(6,'0'))
        : '#5a7ba0';
      riRoleMap[ro.id] = { name: ro.name, color: colorHex };
      return `<div class="ri-role-item" onclick="riSelectRole('${ro.id}')">
        <div class="ri-role-dot" style="background:${colorHex};box-shadow:0 0 6px ${colorHex}55;"></div>
        <div class="ri-role-name">${escHtml(ro.name)}</div>
        <div class="ri-role-arrow">→</div>
      </div>`;
    }).join('');
  } catch(e) { list.innerHTML = '<div style="color:var(--danger);">โหลดไม่ได้</div>'; }
}

async function riSelectRole(roleId) {
  const meta = riRoleMap[roleId] || { name: roleId, color: '#5a7ba0' };
  document.getElementById('ri-role-name').textContent = meta.name;
  document.getElementById('ri-role-name').style.color = meta.color;
  document.getElementById('ri-panel').style.display = 'block';
  document.getElementById('ri-channel-list').innerHTML = '<div style="color:var(--muted);padding:12px;font-size:13px;">⏳ กำลังโหลดข้อมูลห้อง...</div>';
  document.getElementById('ri-panel').scrollIntoView({behavior:'smooth', block:'start'});

  try {
    const r = await fetch(`${API_BASE}/api/role-channels?token=${encodeURIComponent(getToken())}&role_id=${roleId}`);
    if (!r.ok) throw new Error();
    riAllChannels = await r.json();
    riCurrentFilter = 'all';
    riRenderChannels();

    const canSee  = riAllChannels.filter(c => c.can_view).length;
    const cantSee = riAllChannels.filter(c => !c.can_view).length;
    document.getElementById('ri-can-count').textContent  = `เห็น ${canSee} ห้อง`;
    document.getElementById('ri-cant-count').textContent = `ไม่เห็น ${cantSee} ห้อง`;
  } catch(e) {
    document.getElementById('ri-channel-list').innerHTML = '<div style="color:var(--danger);padding:12px;">โหลดไม่ได้ ลองใหม่</div>';
  }
}

function riRenderChannels() {
  const list = document.getElementById('ri-channel-list');
  const typeIcon = t => t === 'TextChannel' ? '#' : t === 'VoiceChannel' ? '♪' : '■';
  const filtered = riAllChannels.filter(ch => {
    if (riCurrentFilter === 'can')  return ch.can_view;
    if (riCurrentFilter === 'cant') return !ch.can_view;
    return true;
  });

  // Group by category
  const groups = {};
  filtered.forEach(ch => {
    const cat = ch.category || '—';
    if (!groups[cat]) groups[cat] = [];
    groups[cat].push(ch);
  });

  list.innerHTML = Object.entries(groups).map(([cat, chs]) => `
    <div style="margin-top:8px;">
      <div style="font-size:10px;font-weight:700;color:var(--muted2);text-transform:uppercase;
                  letter-spacing:.6px;padding:4px 10px;margin-bottom:2px;">${escHtml(cat)}</div>
      ${chs.map(ch => `
        <div class="ri-ch-row">
          <div class="ri-ch-icon">${typeIcon(ch.type)}</div>
          <div style="flex:1;min-width:0;">
            <div class="ri-ch-name">${escHtml(ch.name)}</div>
          </div>
          <div class="ri-ch-badges">
            ${ch.can_view
              ? `<span class="ri-badge-ok">เห็น</span>`
              : `<span class="ri-badge-no"><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg> ไม่เห็น</span>`}
            ${ch.can_view
              ? (ch.can_send
                  ? `<span class="ri-badge-ok">พิมพ์ได้</span>`
                  : `<span class="ri-badge-no">พิมพ์ไม่ได้</span>`)
              : ''}
          </div>
        </div>`).join('')}
    </div>`).join('') || '<div style="color:var(--muted);padding:14px;font-size:13px;text-align:center;">ไม่มีห้องที่ตรงตามเงื่อนไข</div>';

  // Highlight active filter btn
  ['all','can','cant'].forEach(f => {
    const btn = document.getElementById(`ri-filter-${f}`);
    if (btn) btn.style.background = f === riCurrentFilter ? 'var(--primary-glow)' : '';
  });
}

function riFilter(f) { riCurrentFilter = f; riRenderChannels(); }
function riClose()   { document.getElementById('ri-panel').style.display = 'none'; }

// ─── CHARTS ───────────────────────────────────────────────────────
let chartProtection = null;
let chartServer = null;

function initCharts() {
  const chartDefaults = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { display: false }, tooltip: { enabled: true } },
  };

  // Protection donut chart
  const ctxP = document.getElementById('chart-protection');
  if (ctxP && !chartProtection) {
    chartProtection = new Chart(ctxP, {
      type: 'doughnut',
      data: {
        labels: ['Anti-Nuke','Anti-Raid','Anti-Spam','ทั่วไป'],
        datasets: [{
          data: [0, 0, 0, 0],
          backgroundColor: ['rgba(255,71,87,.8)','rgba(255,165,2,.8)','rgba(59,110,248,.8)','rgba(0,200,150,.8)'],
          borderColor: 'transparent',
          borderWidth: 0,
          hoverOffset: 4,
        }]
      },
      options: {
        ...chartDefaults,
        cutout: '72%',
        plugins: {
          legend: {
            display: true,
            position: 'right',
            labels: { color: '#5a7ba0', font: { size: 10, family: 'Kanit' }, boxWidth: 10, padding: 8 }
          },
          tooltip: {
            callbacks: {
              label: (ctx) => ` ${ctx.label}: ${ctx.raw} ระบบ`
            }
          }
        }
      }
    });
  }

  // Server bar chart
  const ctxS = document.getElementById('chart-server');
  if (ctxS && !chartServer) {
    chartServer = new Chart(ctxS, {
      type: 'bar',
      data: {
        labels: ['สมาชิก','ออนไลน์','ช่อง','ยศ'],
        datasets: [{
          data: [0, 0, 0, 0],
          backgroundColor: [
            'rgba(59,110,248,.7)',
            'rgba(0,200,150,.7)',
            'rgba(0,212,255,.7)',
            'rgba(168,85,247,.7)',
          ],
          borderRadius: 6,
          borderSkipped: false,
        }]
      },
      options: {
        ...chartDefaults,
        scales: {
          x: { ticks: { color: '#5a7ba0', font: { size: 10, family: 'Kanit' } }, grid: { display: false }, border: { display: false } },
          y: { ticks: { color: '#3d5478', font: { size: 10, family: 'Kanit' }, maxTicksLimit: 4 }, grid: { color: 'rgba(30,45,69,.6)' }, border: { display: false } }
        }
      }
    });
  }
}

function updateCharts(cfg, stats) {
  if (!chartProtection || !chartServer) return;

  // Count enabled per category
  const NUKE_KEYS  = ['anti_ban','anti_kick','anti_ch_create','anti_ch_delete','anti_ch_update','anti_role_create','anti_role_delete','anti_role_update','anti_role_give','anti_webhook_create','anti_webhook_delete','anti_bot_add','anti_guild_update','anti_vanity','anti_prune','anti_integration'];
  const RAID_KEYS  = ['anti_join_flood','anti_account_age','anti_no_avatar','server_lockdown'];
  const SPAM_KEYS  = ['anti_mass_mentions','anti_text_spam','anti_link_spam','anti_att_spam','anti_emoji_spam'];
  const EXTRA_KEYS = ['automod','voiceabuse'];
  const countOn = keys => keys.filter(k => (cfg[k]||{}).enabled).length;

  chartProtection.data.datasets[0].data = [countOn(NUKE_KEYS), countOn(RAID_KEYS), countOn(SPAM_KEYS), countOn(EXTRA_KEYS)];
  chartProtection.update('none');

  if (stats) {
    chartServer.data.datasets[0].data = [stats.member_count||0, stats.online_count||0, stats.channel_count||0, stats.role_count||0];
    chartServer.update('none');
  }
}

// ─── INIT ─────────────────────────────────────────────────────────
(function() {
  if (getToken()) showApp();
  // Init Lucide icons
  if (window.lucide) lucide.createIcons();
})();
</script>
</body>
</html>"""

async def page_index(req):
    html = DASHBOARD_HTML.replace(
        'const API_BASE = "http://localhost:8080";',
        f'const API_BASE = "{API_BASE_URL}";'
    )
    return web.Response(text=html, content_type="text/html", charset="utf-8")

# ══════════════════════════════════════════════════════════════════
#  WEB SERVER
# ══════════════════════════════════════════════════════════════════
async def run_web():
    app = web.Application()
    app.router.add_get("/",                           page_index)
    app.router.add_get("/dashboard",                  page_index)
    app.router.add_get("/api/verify",                 api_verify)
    app.router.add_get("/api/config",                 api_get_config)
    app.router.add_post("/api/config",                api_post_config)
    app.router.add_get("/api/stats",                  api_stats)
    app.router.add_get("/api/logs",                   api_logs)
    app.router.add_post("/api/lockdown",              api_lockdown)
    app.router.add_post("/api/advanced-manage",       api_advanced_manage)
    app.router.add_get("/api/roles",                  api_roles)
    app.router.add_get("/api/members",                api_members)
    app.router.add_get("/api/member-detail",          api_member_detail)
    app.router.add_post("/api/member-exemptions",     api_save_member_exemptions)
    app.router.add_get("/api/role-channels",          api_role_channels)
    app.router.add_get("/api/suspicious-alerts",      api_suspicious_alerts)
    app.router.add_post("/api/suspicious-alerts/read",api_mark_alert_read)
    app.router.add_get("/api/member-actions",         api_member_actions)
    app.router.add_post("/api/log-channels/create",   api_create_log_channel)
    app.router.add_post("/api/log-channels/delete",   api_delete_log_channel)
    app.router.add_route("OPTIONS", "/{tail:.*}",     api_options)
    runner = web.AppRunner(app)
    await runner.setup()
    await web.TCPSite(runner, "0.0.0.0", PORT).start()
    log.info(f"🌐 Web รันที่ port {PORT}")
    while True:
        await asyncio.sleep(3600)

# ══════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════
async def main():
    await asyncio.gather(bot.start(BOT_TOKEN), run_web())

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("บอทหยุดทำงาน")
