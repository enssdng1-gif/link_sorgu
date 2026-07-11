import logging
import re
import requests
import time
import os
from threading import Thread
from concurrent.futures import ThreadPoolExecutor
from flask import Flask
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    ApplicationBuilder, ContextTypes,
    CommandHandler, MessageHandler,
    CallbackQueryHandler, filters
)

# ── Ayarlar ────────────────────────────────────────────────────
TELEGRAM_TOKEN   = os.environ.get("TELEGRAM_BOT_TOKEN", "")
VT_API_KEY       = os.environ.get("VIRUSTOTAL_API_KEY", "")
RAPID_API_KEY    = os.environ.get("RAPIDAPI_KEY", "")
PORT             = int(os.environ.get("PORT", 10000))
# ───────────────────────────────────────────────────────────────

logging.basicConfig(
    format="%(asctime)s | %(levelname)s | %(message)s",
    level=logging.INFO
)
log = logging.getLogger(__name__)

executor = ThreadPoolExecutor(max_workers=8)

# ── Flask (Render'ın botu uyutmaması için) ─────────────────────
flask_app = Flask(__name__)

@flask_app.route("/")
def index():
    return "Bot aktif!", 200

@flask_app.route("/healthz")
def health():
    return "OK", 200

def run_flask():
    flask_app.run(host="0.0.0.0", port=PORT, use_reloader=False)

# ── Yardımcı fonksiyonlar ──────────────────────────────────────
URL_RE = re.compile(r"https?://[^\s]+")

def find_urls(text: str):
    return URL_RE.findall(text)

def fmt_num(n):
    try:
        n = int(n)
        if n >= 1_000_000: return f"{n/1_000_000:.1f}M"
        if n >= 1_000:     return f"{n/1_000:.1f}K"
        return str(n)
    except Exception:
        return str(n) if n else "?"

# ── VirusTotal ─────────────────────────────────────────────────
def vt_scan(url: str) -> str:
    if not VT_API_KEY:
        return "⚠️ VIRUSTOTAL_API_KEY eksik."
    headers = {"x-apikey": VT_API_KEY}
    try:
        r = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers={**headers, "content-type": "application/x-www-form-urlencoded"},
            data={"url": url}, timeout=15
        )
        r.raise_for_status()
        analysis_id = r.json()["data"]["id"]

        for _ in range(12):
            time.sleep(3)
            ar = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers, timeout=10
            )
            ar.raise_for_status()
            d = ar.json()["data"]
            if d["attributes"]["status"] == "completed":
                break

        stats   = d["attributes"]["stats"]
        results = d["attributes"]["results"]
        mal  = stats.get("malicious", 0)
        sus  = stats.get("suspicious", 0)
        harm = stats.get("harmless", 0)
        undet= stats.get("undetected", 0)
        total= mal + sus + harm + undet

        if mal + sus > 0:
            threats = [
                f"• {eng}: {res.get('result','?')}"
                for eng, res in results.items()
                if res.get("category") in ("malicious","suspicious")
            ][:5]
            t_str = "\n".join(threats)
            msg  = "🚨 *TEHLİKELİ LİNK TESPİT EDİLDİ!*\n\n"
            msg += f"🔗 `{url}`\n"
            msg += f"📊 {total} tarayıcıdan *{mal+sus}* tanesi zararlı buldu!\n\n"
            msg += f"*Tespit edilenler:*\n{t_str}\n\n"
            msg += "⛔ Bu linke KESİNLİKLE tıklamayın!"
        else:
            msg  = "✅ *Link Temiz Görünüyor*\n\n"
            msg += f"🔗 `{url}`\n"
            msg += f"📊 {total} güvenlik şirketi taradı, tehlike bulunamadı."
        return msg

    except requests.Timeout:
        return "⏱️ VirusTotal yanıt vermedi. Lütfen tekrar deneyin."
    except Exception as e:
        log.error("VT hata: %s", e)
        return "⚠️ Link taranırken hata oluştu."

# ── Instagram ──────────────────────────────────────────────────
def ig_fetch(username: str):
    if not RAPID_API_KEY:
        return None, "⚠️ RAPIDAPI_KEY eksik."
    try:
        r = requests.get(
            "https://instagram360.p.rapidapi.com/userinfo",
            headers={
                "x-rapidapi-key":  RAPID_API_KEY,
                "x-rapidapi-host": "instagram360.p.rapidapi.com"
            },
            params={"username_or_id": username},
            timeout=12
        )
        log.info("IG status: %s | body: %s", r.status_code, r.text[:300])
        if r.status_code == 404:
            return None, f"❌ *@{username}* bulunamadı."
        if r.status_code == 403:
            return None, "⚠️ API erişim reddedildi. Anahtar geçersiz olabilir."
        if r.status_code == 429:
            return None, "⚠️ Çok fazla istek. Lütfen bekleyip tekrar deneyin."
        r.raise_for_status()
        raw  = r.json()
        data = raw.get("data") or raw
        return data, None
    except requests.Timeout:
        return None, "⏱️ Instagram API 12 saniyede yanıt vermedi. Tekrar deneyin."
    except Exception as e:
        log.error("IG hata: %s", e)
        return None, f"⚠️ Hata: {str(e)[:80]}"

def build_ig_msg(data: dict):
    uname    = data.get("username") or "?"
    name     = data.get("full_name") or data.get("fullname") or ""
    bio      = data.get("biography") or data.get("bio") or ""
    followers= fmt_num(data.get("follower_count") or data.get("followers"))
    following= fmt_num(data.get("following_count") or data.get("following"))
    posts    = fmt_num(data.get("media_count")    or data.get("posts"))
    private  = data.get("is_private", False)
    verified = data.get("is_verified", False)
    pic      = data.get("profile_pic_url_hd") or data.get("profile_pic_url") or ""
    website  = data.get("external_url") or data.get("website") or ""

    badge   = " ✅" if verified else ""
    privacy = "🔒 Gizli" if private else "🌍 Açık"

    lines = [
        "📸 *Instagram Profil Raporu*",
        "━━━━━━━━━━━━━━━━━",
        f"👤 *Ad:* {name}{badge}",
        f"🔖 *Kullanıcı:* @{uname}",
        f"🔐 *Hesap:* {privacy}",
        "━━━━━━━━━━━━━━━━━",
        f"👥 *Takipçi:* {followers}",
        f"➡️ *Takip:* {following}",
        f"🖼️ *Gönderi:* {posts}",
    ]
    if bio:
        lines += ["━━━━━━━━━━━━━━━━━", f"📝 *Bio:* {bio}"]
    if website:
        lines.append(f"🔗 {website}")
    lines.append(f"\n[Profili Görüntüle](https://www.instagram.com/{uname}/)")
    return "\n".join(lines), pic

# ── /start ─────────────────────────────────────────────────────
async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("🔗 Link Güvenlik Taraması", callback_data="info_link")],
        [InlineKeyboardButton("📸 Instagram Profil Sorgula", callback_data="info_ig")],
    ])
    await update.message.reply_text(
        "👋 *Merhaba! Ben Güvenlik & Sorgulama Botuyum.*\n\n"
        "Ne yapmak istersiniz?",
        parse_mode="Markdown",
        reply_markup=kb
    )

# ── Buton geri çağrıları ───────────────────────────────────────
async def on_button(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()

    if q.data == "info_link":
        await q.edit_message_text(
            "🔗 *Link Güvenlik Taraması*\n\n"
            "Bana herhangi bir linki *mesaj olarak* gönderin.\n\n"
            "Örnek:\n`https://suphelisite.com`\n\n"
            "70+ güvenlik şirketi ile analiz edip sonucu bildiririm.",
            parse_mode="Markdown"
        )
    elif q.data == "info_ig":
        await q.edit_message_text(
            "📸 *Instagram Profil Sorgulama*\n\n"
            "Komut: `/ig kullanici_adi`\n\n"
            "Örnek:\n`/ig cristiano`\n\n"
            "Takipçi, gönderi, biyografi ve profil fotoğrafını getiririm.",
            parse_mode="Markdown"
        )

# ── /ig komutu ─────────────────────────────────────────────────
async def cmd_ig(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not ctx.args:
        await update.message.reply_text(
            "📸 Kullanım: `/ig kullanici_adi`\nÖrnek: `/ig cristiano`",
            parse_mode="Markdown"
        )
        return

    username = ctx.args[0].lstrip("@").strip()
    msg = await update.message.reply_text(
        f"🔍 *@{username}* sorgulanıyor...",
        parse_mode="Markdown"
    )

    loop = update.get_bot()._loop if hasattr(update.get_bot(), "_loop") else None
    import asyncio
    data, err = await asyncio.get_event_loop().run_in_executor(
        executor, ig_fetch, username
    )

    if err:
        await msg.edit_text(err, parse_mode="Markdown")
        return

    text, pic = build_ig_msg(data)
    await msg.delete()

    if pic:
        try:
            await update.message.reply_photo(photo=pic, caption=text, parse_mode="Markdown")
            return
        except Exception as e:
            log.warning("Fotoğraf gönderilemedi: %s", e)

    await update.message.reply_text(text, parse_mode="Markdown", disable_web_page_preview=False)

# ── Metin mesajları (link tarama) ──────────────────────────────
async def on_text(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    text = update.message.text or ""
    urls = find_urls(text)

    if not urls:
        await update.message.reply_text(
            "ℹ️ Mesajınızda link bulamadım.\n\n"
            "• Link taramak için `http://` veya `https://` ile başlayan bir link gönderin.\n"
            "• Instagram için `/ig kullanici_adi` yazın.\n"
            "• Menü için /start yazın.",
            parse_mode="Markdown"
        )
        return

    target = urls[0]
    msg = await update.message.reply_text(
        f"🔍 Link analiz ediliyor...\n`{target}`",
        parse_mode="Markdown"
    )

    import asyncio
    report = await asyncio.get_event_loop().run_in_executor(executor, vt_scan, target)
    await msg.edit_text(report, parse_mode="Markdown")

# ── Ana giriş noktası ──────────────────────────────────────────
if __name__ == "__main__":
    if not TELEGRAM_TOKEN:
        raise SystemExit("HATA: TELEGRAM_BOT_TOKEN eksik!")
    if not VT_API_KEY:
        log.warning("VIRUSTOTAL_API_KEY eksik — link tarama çalışmaz.")
    if not RAPID_API_KEY:
        log.warning("RAPIDAPI_KEY eksik — Instagram sorgusu çalışmaz.")

    Thread(target=run_flask, daemon=True).start()
    log.info("Flask sunucu başlatıldı (port %s)", PORT)

    app = ApplicationBuilder().token(TELEGRAM_TOKEN).build()
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("ig",    cmd_ig))
    app.add_handler(CallbackQueryHandler(on_button))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_text))

    log.info("Bot polling başlatıldı!")
    app.run_polling(drop_pending_updates=True)
