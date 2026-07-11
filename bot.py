import logging
import re
import requests
import time
import os
import html
import asyncio
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

# ── Kısaltılmış Link Çözücü ────────────────────────────────────
def resolve_url(url: str) -> str:
    try:
        r = requests.head(url, allow_redirects=True, timeout=5)
        return r.url
    except Exception:
        return url

# ── VirusTotal ─────────────────────────────────────────────────
def vt_scan_url(url: str) -> str:
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

def vt_scan_file(file_bytes: bytes, filename: str) -> str:
    if not VT_API_KEY:
        return "⚠️ VIRUSTOTAL_API_KEY eksik."
    headers = {"x-apikey": VT_API_KEY}
    try:
        files = {"file": (filename, file_bytes)}
        r = requests.post(
            "https://www.virustotal.com/api/v3/files",
            headers=headers,
            files=files, timeout=30
        )
        r.raise_for_status()
        analysis_id = r.json()["data"]["id"]

        for _ in range(15):
            time.sleep(4)
            ar = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers, timeout=10
            )
            ar.raise_for_status()
            d = ar.json()["data"]
            if d["attributes"]["status"] == "completed":
                break

        stats = d["attributes"]["stats"]
        results = d["attributes"]["results"]
        mal = stats.get("malicious", 0)
        sus = stats.get("suspicious", 0)
        total = sum(stats.values())

        if mal + sus > 0:
            threats = [
                f"• {eng}: {res.get('result','?')}"
                for eng, res in results.items()
                if res.get("category") in ("malicious","suspicious")
            ][:5]
            msg  = f"🚨 <b>TEHLİKELİ DOSYA:</b> <code>{html.escape(filename)}</code>\n\n"
            msg += f"📊 {total} antivirüsten <b>{mal+sus}</b> tanesi zararlı buldu!\n\n"
            msg += f"<b>Tehditler:</b>\n{html.escape(chr(10).join(threats))}\n\n"
            msg += "⛔ Dosyayı ASLA AÇMAYIN!"
        else:
            msg  = f"✅ <b>Dosya Temiz:</b> <code>{html.escape(filename)}</code>\n\n"
            msg += f"📊 {total} antivirüs taradı, hiçbir tehdit bulunamadı."
        return msg
    except requests.Timeout:
        return "⏱️ VirusTotal zaman aşımına uğradı."
    except Exception as e:
        log.error("VT file error: %s", e)
        return "⚠️ Dosya taranırken hata oluştu."

def vt_scan_ip(ip: str) -> dict:
    if not VT_API_KEY:
        return {}
    headers = {"x-apikey": VT_API_KEY}
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers=headers, timeout=10)
        if r.status_code == 200:
            stats = r.json()["data"]["attributes"]["last_analysis_stats"]
            return {"malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0)}
    except:
        pass
    return {}

# ── Data Breach (E-posta Sızıntı) ──────────────────────────────
def check_breach(email: str) -> str:
    try:
        r = requests.get(f"https://api.xposedornot.com/v1/check-email/{email}", timeout=10)
        if r.status_code == 404:
            return f"✅ <b>Tebrikler!</b>\n\n<code>{html.escape(email)}</code> adresi hiçbir sızıntı veritabanında bulunmadı. Güvendesiniz."
        
        if r.status_code == 200:
            data = r.json()
            breaches = data.get("breaches", [[]])[0]
            count = len(breaches)
            
            msg = f"🚨 <b>DİKKAT! SIZINTI TESPİT EDİLDİ!</b>\n\n"
            msg += f"<code>{html.escape(email)}</code> adresi <b>{count}</b> farklı hacker saldırısında sızdırılmış!\n\n"
            msg += "<b>Sızdırıldığı Bazı Siteler:</b>\n"
            for b in breaches[:10]:
                msg += f"• {b}\n"
            if count > 10:
                msg += f"...ve {count-10} site daha.\n"
            msg += "\n⚠️ <i>Şifrelerinizi hemen değiştirmeniz tavsiye edilir!</i>"
            return msg
        return "⚠️ Sızıntı veritabanına bağlanılamadı."
    except Exception as e:
        log.error("Breach error: %s", e)
        return "⚠️ Hata oluştu."

# ── IP OSINT ───────────────────────────────────────────────────
def check_ip(ip: str) -> str:
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,city,isp,org,query", timeout=10)
        data = r.json()
        if data.get("status") != "success":
            return f"❌ <b>Hata:</b> IP adresi çözümlenemedi."
        
        msg = f"🌍 <b>IP Bilgi Raporu:</b> <code>{html.escape(data.get('query'))}</code>\n\n"
        msg += f"📍 <b>Konum:</b> {data.get('city', '?')}, {data.get('country', '?')}\n"
        msg += f"🏢 <b>İnternet Sağlayıcı:</b> {data.get('isp', '?')}\n"
        msg += f"🏢 <b>Organizasyon:</b> {data.get('org', '?')}\n"

        # VT Check
        vt_stats = vt_scan_ip(data.get('query'))
        if vt_stats:
            mal = vt_stats.get("malicious", 0)
            if mal > 0:
                msg += f"\n🚨 <b>Güvenlik Uyarısi:</b> VirusTotal bu IP'yi {mal} kez <b>ZARARLI</b> olarak işaretlemiş!"
            else:
                msg += f"\n✅ <b>Güvenlik:</b> VirusTotal bu IP'de tehdit bulmadı."
        return msg
    except Exception as e:
        return "⚠️ IP adresi sorgulanırken hata oluştu."

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
    
    category = html.escape(str(data.get("category_name") or data.get("category") or ""))
    is_biz   = data.get("is_business", False)
    email    = html.escape(str(data.get("public_email") or ""))
    phone    = html.escape(str(data.get("public_phone_number") or data.get("contact_phone_number") or ""))
    
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
        for idx, elink in enumerate(extra_links[:3]): 
            lines.append(f"🔗 <b>Bağlantı {idx+1}:</b> {elink}")

    lines.append(f"\n<a href='https://www.instagram.com/{uname}/'>Profili Görüntüle</a>")
    return "\n".join(lines), pic

# ── KOMUTLAR ───────────────────────────────────────────────────

async def cmd_menu(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("🔗 Link Sorgula", callback_data="info_link"),
         InlineKeyboardButton("📸 Insta Sorgula", callback_data="info_ig")],
        [InlineKeyboardButton("📧 İhlal Sorgula", callback_data="info_ihlal"),
         InlineKeyboardButton("🌍 IP/Domain Sorgula", callback_data="info_ip")],
        [InlineKeyboardButton("📁 Dosya/Virüs Tarama", callback_data="info_file")]
    ])
    await update.message.reply_text(
        "👋 <b>Siber Güvenlik & OSINT Ana Menüsü</b>\n\n"
        "Güçlü analiz araçlarına hoş geldiniz. Ne yapmak istersiniz?\n\n"
        "👉 <code>/ig kullanıcı_adı</code> : Instagram profil analizi\n"
        "👉 <code>/ihlal ornek@gmail.com</code> : Veri sızıntı kontrolü\n"
        "👉 <code>/ip adres</code> : IP veya Domain araştırması\n"
        "👉 <code>/link</code> : URL/Link güvenlik analizi\n"
        "👉 <b>Sadece link/dosya atın:</b> Otomatik analiz başlasın!",
        parse_mode="HTML",
        reply_markup=kb
    )

async def cmd_ig(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not ctx.args:
        await update.message.reply_text(
            "📸 <b>Instagram Sorgulama Modu</b>\n\n"
            "Kullanım: <code>/ig cristiano</code>", parse_mode="HTML"
        )
        return

    username = ctx.args[0].lstrip("@").strip()
    msg = await update.message.reply_text(f"🔍 <b>@{html.escape(username)}</b> tüm detaylarıyla sorgulanıyor...", parse_mode="HTML")

    loop = asyncio.get_running_loop()
    try:
        data, err = await asyncio.wait_for(loop.run_in_executor(executor, ig_fetch, username), timeout=15.0)
    except asyncio.TimeoutError:
        await msg.edit_text("⏱️ <b>Zaman aşımı!</b>", parse_mode="HTML")
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
    await update.message.reply_text(
        "🔗 <b>Link Sorgulama Modu</b>\n\nBana herhangi bir linki gönderin. Kısaltılmışsa gerçek adresini bulup virüs taraması yaparım.",
        parse_mode="HTML"
    )

async def cmd_reset(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    blank_space = ".\n" * 50
    await update.message.reply_text(
        f"{blank_space}🧹 <b>Sohbet Temizlendi!</b>\n\nMenüyü görmek için /menu yazabilirsiniz.",
        parse_mode="HTML",
        reply_markup=ReplyKeyboardRemove()
    )

async def cmd_ihlal(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not ctx.args:
        await update.message.reply_text("📧 Kullanım: <code>/ihlal ornek@gmail.com</code>", parse_mode="HTML")
        return
    email = ctx.args[0].strip()
    msg = await update.message.reply_text(f"🔍 <b>{html.escape(email)}</b> sızıntı veritabanlarında aranıyor...", parse_mode="HTML")
    
    loop = asyncio.get_running_loop()
    report = await loop.run_in_executor(executor, check_breach, email)
    await msg.edit_text(report, parse_mode="HTML")

async def cmd_ip(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not ctx.args:
        await update.message.reply_text("🌍 Kullanım: <code>/ip 1.1.1.1</code> veya <code>/ip siteadi.com</code>", parse_mode="HTML")
        return
    ip_addr = ctx.args[0].strip()
    msg = await update.message.reply_text(f"🔍 <b>{html.escape(ip_addr)}</b> lokasyon ve güvenlik taraması yapılıyor...", parse_mode="HTML")
    
    loop = asyncio.get_running_loop()
    report = await loop.run_in_executor(executor, check_ip, ip_addr)
    await msg.edit_text(report, parse_mode="HTML")

# ── Buton Geri Çağrıları ───────────────────────────────────────
async def on_button(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()

    if q.data == "info_link":
        await q.edit_message_text("🔗 Bize bir link atın, gizli adresini çözüp virüs taramasından geçirelim.")
    elif q.data == "info_ig":
        await q.edit_message_text("📸 Kullanım: `/ig kullanici_adi`", parse_mode="Markdown")
    elif q.data == "info_ihlal":
        await q.edit_message_text("📧 Kullanım: `/ihlal emailiniz@gmail.com`", parse_mode="Markdown")
    elif q.data == "info_ip":
        await q.edit_message_text("🌍 Kullanım: `/ip 8.8.8.8`", parse_mode="Markdown")
    elif q.data == "info_file":
        await q.edit_message_text("📁 Analiz edilmesini istediğiniz herhangi bir dosyayı, fotoğrafı veya APK'yı direkt mesaj olarak gönderin.")

# ── Mesaj Okuyucular (Link ve Dosya) ───────────────────────────
async def on_text(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    text = update.message.text or ""
    urls = find_urls(text)

    if not urls:
        await update.message.reply_text(
            "ℹ️ Mesajınızda geçerli bir komut veya link bulamadım.\nMenü için /menu yazın.",
            parse_mode="HTML"
        )
        return

    original_url = urls[0]
    msg = await update.message.reply_text("🔍 Link kontrol ediliyor...", parse_mode="HTML")

    loop = asyncio.get_running_loop()
    # Kısaltılmış link çözücü
    target_url = await loop.run_in_executor(executor, resolve_url, original_url)
    
    if target_url != original_url:
        await msg.edit_text(f"🔗 <b>Link Çözüldü!</b>\nAsıl adres: <code>{html.escape(target_url)}</code>\n\nVirustotal'de analiz ediliyor...", parse_mode="HTML")
    else:
        await msg.edit_text(f"🔍 Virustotal'de analiz ediliyor...\n<code>{html.escape(target_url)}</code>\n\n<i>(Bu işlem yaklaşık 30 sn sürebilir)</i>", parse_mode="HTML")

    report = await loop.run_in_executor(executor, vt_scan_url, target_url)
    await msg.edit_text(report, parse_mode="HTML")

async def on_file(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    doc = update.message.document or update.message.photo[-1] if update.message.photo else None
    if not doc: return

    # Dosya boyutu kontrolü (Telegram API genel bot indirme limiti 20MB'dır)
    file_size = getattr(doc, 'file_size', 0)
    if file_size > 20 * 1024 * 1024:
        await update.message.reply_text("⚠️ Dosya boyutu 20 MB'dan büyük olduğu için Telegram limitlerine takıldı.")
        return

    filename = getattr(doc, 'file_name', "dosya.file")
    msg = await update.message.reply_text(f"📥 Dosya indiriliyor: <code>{html.escape(filename)}</code>", parse_mode="HTML")

    try:
        # Telegramdan dosyayı indir
        file_obj = await ctx.bot.get_file(doc.file_id)
        byte_array = await file_obj.download_as_bytearray()

        await msg.edit_text(f"🔍 Dosya VirusTotal'e yükleniyor ve analiz ediliyor...\n\n<i>Lütfen 30-40 saniye bekleyin.</i>", parse_mode="HTML")
        
        loop = asyncio.get_running_loop()
        report = await loop.run_in_executor(executor, vt_scan_file, byte_array, filename)
        await msg.edit_text(report, parse_mode="HTML")

    except Exception as e:
        log.error("File download error: %s", e)
        await msg.edit_text("⚠️ Dosya indirilirken veya analiz edilirken bir hata oluştu.")

# ── Ana giriş noktası ──────────────────────────────────────────
if __name__ == "__main__":
    if not TELEGRAM_TOKEN:
        raise SystemExit("HATA: TELEGRAM_BOT_TOKEN eksik!")
    
    Thread(target=run_flask, daemon=True).start()

    app = ApplicationBuilder().token(TELEGRAM_TOKEN).build()
    
    app.add_handler(CommandHandler(["start", "menu"], cmd_menu))
    app.add_handler(CommandHandler("ig", cmd_ig))
    app.add_handler(CommandHandler("link", cmd_link))
    app.add_handler(CommandHandler("reset", cmd_reset))
    app.add_handler(CommandHandler("ihlal", cmd_ihlal))
    app.add_handler(CommandHandler("ip", cmd_ip))
    
    app.add_handler(CallbackQueryHandler(on_button))
    # Tüm medya tipleri ve dokümanları yakalar
    app.add_handler(MessageHandler(filters.Document.ALL | filters.PHOTO | filters.VIDEO | filters.AUDIO, on_file))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_text))

    log.info("Siber Güvenlik Botu başlatıldı!")
    app.run_polling(drop_pending_updates=True)
