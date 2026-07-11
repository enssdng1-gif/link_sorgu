import logging
import re
import requests
import time
import os
import html
from threading import Thread
from concurrent.futures import ThreadPoolExecutor
from flask import Flask
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, ReplyKeyboardRemove
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
            msg  = "🚨 <b>TEHLİKELİ LİNK TESPİT EDİLDİ!</b>\n\n"
            msg += f"🔗 <code>{html.escape(url)}</code>\n"
            msg += f"📊 {total} tarayıcıdan <b>{mal+sus}</b> tanesi zararlı buldu!\n\n"
            msg += f"<b>Tespit edilenler:</b>\n{html.escape(t_str)}\n\n"
            msg += "⛔ Bu linke KESİNLİKLE tıklamayın!"
        else:
            msg  = "✅ <b>Link Temiz Görünüyor</b>\n\n"
            msg += f"🔗 <code>{html.escape(url)}</code>\n"
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
        if r.status_code == 404:
            return None, f"❌ <b>@{html.escape(username)}</b> bulunamadı."
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
        return None, f"⚠️ Hata oluştu."

def build_ig_msg(data: dict):
    uname    = html.escape(str(data.get("username") or "?"))
    name     = html.escape(str(data.get("full_name") or data.get("fullname") or ""))
    bio      = html.escape(str(data.get("biography") or data.get("bio") or ""))
    followers= fmt_num(data.get("follower_count") or data.get("followers"))
    following= fmt_num(data.get("following_count") or data.get("following"))
    posts    = fmt_num(data.get("media_count")    or data.get("posts"))
    private  = data.get("is_private", False)
    verified = data.get("is_verified", False)
    pic      = data.get("profile_pic_url_hd") or data.get("profile_pic_url") or ""
    website  = html.escape(str(data.get("external_url") or data.get("website") or ""))
    
    # Yeni Detaylar
    category = html.escape(str(data.get("category_name") or data.get("category") or ""))
    is_biz   = data.get("is_business", False)
    email    = html.escape(str(data.get("public_email") or ""))
    phone    = html.escape(str(data.get("public_phone_number") or data.get("contact_phone_number") or ""))
    
    # Çoklu Linkler
    bio_links = data.get("bio_links", [])
    extra_links = []
    for link in bio_links:
        url = link.get("url")
        if url and url != website:
            extra_links.append(html.escape(url))

    badge   = " ✅" if verified else ""
    privacy = "🔒 Gizli" if private else "🌍 Açık"
    biz_txt = "🏢 İşletme/İçerik Üretici" if is_biz else "👤 Kişisel Hesap"

    lines = [
        "📸 <b>Instagram Profil Raporu</b>",
        "━━━━━━━━━━━━━━━━━",
        f"👤 <b>Ad:</b> {name}{badge}",
        f"🔖 <b>Kullanıcı:</b> @{uname}",
        f"🔐 <b>Durum:</b> {privacy} | {biz_txt}"
    ]
    
    if category and category != "None":
        lines.append(f"🏷️ <b>Kategori:</b> {category}")
        
    lines += [
        "━━━━━━━━━━━━━━━━━",
        f"👥 <b>Takipçi:</b> {followers}",
        f"➡️ <b>Takip:</b> {following}",
        f"🖼️ <b>Gönderi:</b> {posts}",
    ]
    
    if email or phone:
        lines.append("━━━━━━━━━━━━━━━━━")
        if email: lines.append(f"📧 <b>E-posta:</b> {email}")
        if phone: lines.append(f"☎️ <b>Telefon:</b> {phone}")

    if bio:
        lines += ["━━━━━━━━━━━━━━━━━", f"📝 <b>Biyografi:</b>\n{bio}"]
        
    if website or extra_links:
        lines.append("━━━━━━━━━━━━━━━━━")
        if website:
            lines.append(f"🔗 <b>Web Sitesi:</b> {website}")
        for idx, elink in enumerate(extra_links[:3]): # Sadece ilk 3 ekstra linki göster
            lines.append(f"🔗 <b>Bağlantı {idx+1}:</b> {elink}")

    lines.append(f"\n<a href='https://www.instagram.com/{uname}/'>Profili Görüntüle</a>")
    return "\n".join(lines), pic

# ── KOMUTLAR ───────────────────────────────────────────────────

async def cmd_menu(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """/menu ve /start komutu"""
    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("🔗 Link Sorgula", callback_data="info_link")],
        [InlineKeyboardButton("📸 Insta Sorgula", callback_data="info_ig")],
    ])
    await update.message.reply_text(
        "👋 <b>Ana Menüye Hoş Geldiniz!</b>\n\n"
        "Ne yapmak istersiniz?\n\n"
        "👉 <code>/ig kullanıcı_adı</code> : Instagram profil analizi\n"
        "👉 <code>/link</code> : URL/Link güvenlik analizi\n"
        "👉 <code>/reset</code> : Sohbet ekranını temizle",
        parse_mode="HTML",
        reply_markup=kb
    )

async def cmd_ig(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """/ig komutu"""
    if not ctx.args:
        await update.message.reply_text(
            "📸 <b>Instagram Sorgulama Modu</b>\n\n"
            "Lütfen komutun yanına kullanıcı adını yazın.\n\n"
            "👉 <b>Örnek:</b> <code>/ig cristiano</code>\n"
            "👉 <b>Örnek:</b> <code>/ig enexs.qx0</code>",
            parse_mode="HTML"
        )
        return

    username = ctx.args[0].lstrip("@").strip()
    msg = await update.message.reply_text(
        f"🔍 <b>@{html.escape(username)}</b> tüm detaylarıyla sorgulanıyor...",
        parse_mode="HTML"
    )

    import asyncio
    loop = asyncio.get_running_loop()
    try:
        data, err = await asyncio.wait_for(
            loop.run_in_executor(executor, ig_fetch, username),
            timeout=15.0
        )
    except asyncio.TimeoutError:
        await msg.edit_text("⏱️ <b>Zaman aşımı!</b> Instagram API yanıt vermedi.", parse_mode="HTML")
        return

    if err:
        await msg.edit_text(err, parse_mode="HTML")
        return

    text, pic = build_ig_msg(data)
    await msg.delete()

    if pic:
        try:
            await update.message.reply_photo(photo=pic, caption=text, parse_mode="HTML")
            return
        except Exception as e:
            log.warning("Fotoğraf gönderilemedi: %s", e)

    await update.message.reply_text(text, parse_mode="HTML", disable_web_page_preview=True)

async def cmd_link(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """/link komutu"""
    await update.message.reply_text(
        "🔗 <b>Link Sorgulama Modu</b>\n\n"
        "Lütfen taramak istediğiniz linki doğrudan mesaj olarak gönderin.\n\n"
        "👉 <b>Örnek:</b> <code>https://testsafebrowsing.appspot.com/s/malware.html</code>",
        parse_mode="HTML"
    )

async def cmd_reset(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """/reset komutu - Telegram'da eski mesajları silmek botlar için kısıtlıdır, bu yüzden temiz bir sayfa açar."""
    # Bot sadece kendi mesajlarını ve eğer admin yetkisi varsa silebilir.
    # Özel mesajda kullanıcının mesajlarını silemez. Bu yüzden bol boşluk bırakarak ekranı temizliyoruz.
    blank_space = ".\n" * 50
    await update.message.reply_text(
        f"{blank_space}🧹 <b>Sohbet Temizlendi!</b>\n\n"
        "Menüyü görmek için /menu yazabilirsiniz.",
        parse_mode="HTML",
        reply_markup=ReplyKeyboardRemove()
    )

# ── Buton Geri Çağrıları ───────────────────────────────────────
async def on_button(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()

    if q.data == "info_link":
        await q.edit_message_text(
            "🔗 <b>Link Güvenlik Taraması</b>\n\n"
            "Bana herhangi bir linki <b>mesaj olarak</b> gönderin.\n\n"
            "Örnek:\n<code>https://suphelisite.com</code>\n\n"
            "VirusTotal üzerinden tarayıp sonucu bildiririm.",
            parse_mode="HTML"
        )
    elif q.data == "info_ig":
        await q.edit_message_text(
            "📸 <b>Instagram Profil Sorgulama</b>\n\n"
            "Komut: <code>/ig kullanici_adi</code>\n\n"
            "Örnek:\n<code>/ig cristiano</code>",
            parse_mode="HTML"
        )

# ── Metin mesajları (link tarama) ──────────────────────────────
async def on_text(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    text = update.message.text or ""
    urls = find_urls(text)

    if not urls:
        await update.message.reply_text(
            "ℹ️ Mesajınızda geçerli bir link bulamadım.\n\n"
            "👉 Link taramak için <code>http://</code> ile başlayan bir mesaj atın.\n"
            "👉 Instagram için <code>/ig kullanici_adi</code> yazın.\n"
            "👉 Menü için /menu yazın.",
            parse_mode="HTML"
        )
        return

    target = urls[0]
    msg = await update.message.reply_text(
        f"🔍 Link Virustotal'de analiz ediliyor...\n<code>{html.escape(target)}</code>\n\n<i>(Bu işlem yaklaşık 30 saniye sürebilir, lütfen bekleyin...)</i>",
        parse_mode="HTML"
    )

    import asyncio
    report = await asyncio.get_event_loop().run_in_executor(executor, vt_scan, target)
    await msg.edit_text(report, parse_mode="HTML")

# ── Ana giriş noktası ──────────────────────────────────────────
if __name__ == "__main__":
    if not TELEGRAM_TOKEN:
        raise SystemExit("HATA: TELEGRAM_BOT_TOKEN eksik!")
    
    Thread(target=run_flask, daemon=True).start()

    app = ApplicationBuilder().token(TELEGRAM_TOKEN).build()
    
    # Yeni Komutlar eklendi
    app.add_handler(CommandHandler(["start", "menu", "menü"], cmd_menu))
    app.add_handler(CommandHandler("ig", cmd_ig))
    app.add_handler(CommandHandler("link", cmd_link))
    app.add_handler(CommandHandler("reset", cmd_reset))
    
    app.add_handler(CallbackQueryHandler(on_button))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_text))

    log.info("Bot başlatıldı!")
    app.run_polling(drop_pending_updates=True)
