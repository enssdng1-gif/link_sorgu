import logging
import re
import requests
import time
import os
import asyncio
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from threading import Thread
from flask import Flask
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ApplicationBuilder, ContextTypes, CommandHandler, MessageHandler, CallbackQueryHandler, filters

executor = ThreadPoolExecutor(max_workers=4)

# --- AYARLAR KISMI ---
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
RAPIDAPI_KEY = os.environ.get("RAPIDAPI_KEY")
# ------------------------------------------------------------------------

# Render Web Service için basit bir web sunucusu (Botun kapanmasını engeller)
app = Flask(__name__)
@app.route('/')
def home():
    return "Bot Çalışıyor!"

@app.route('/healthz')
def health():
    return "OK"

def run_web_server():
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)

# Log ayarları
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

# ===================== LINK TARAMA FONKSİYONLARI =====================

def extract_urls(text):
    """Metin içindeki URL'leri bulur."""
    url_pattern = re.compile(r'https?://[^\s]+')
    return url_pattern.findall(text)

def check_url_virustotal(url):
    """URL'yi VirusTotal API'si ile tarar."""
    vt_url = "https://www.virustotal.com/api/v3/urls"
    headers = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY,
        "content-type": "application/x-www-form-urlencoded"
    }
    data = {"url": url}

    try:
        response = requests.post(vt_url, headers=headers, data=data)
        response.raise_for_status()
        result_id = response.json().get('data', {}).get('id')

        if not result_id:
            return "❌ VirusTotal'den analiz ID'si alınamadı."

        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{result_id}"

        for _ in range(10):
            analysis_response = requests.get(analysis_url, headers={"x-apikey": VIRUSTOTAL_API_KEY})
            analysis_response.raise_for_status()
            data_r = analysis_response.json().get('data', {})
            status = data_r.get('attributes', {}).get('status')
            if status == 'completed':
                break
            time.sleep(3)

        stats = data_r.get('attributes', {}).get('stats', {})
        results = data_r.get('attributes', {}).get('results', {})

        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        harmless = stats.get('harmless', 0)
        undetected = stats.get('undetected', 0)
        total_scanners = malicious + suspicious + harmless + undetected

        if malicious > 0 or suspicious > 0:
            threats = []
            for engine, result in results.items():
                if result.get('category') in ['malicious', 'suspicious']:
                    threat_name = result.get('result', 'Bilinmeyen Tehdit')
                    threats.append(f"• {engine}: {threat_name}")

            threats_str = "\n".join(threats[:5])
            if len(threats) > 5:
                threats_str += f"\n...ve {len(threats)-5} şirket daha."

            report = f"🚨 *DİKKAT! TEHLİKELİ LİNK TESPİT EDİLDİ!* 🚨\n\n"
            report += f"🔗 Taranan Link: `{url}`\n"
            report += f"📊 Sonuç: {total_scanners} güvenlik şirketinden *{malicious + suspicious}* tanesi zararlı/şüpheli buldu!\n\n"
            report += f"*Tespit Edilen Bazı Tehditler:*\n{threats_str}\n\n"
            report += "⛔ Lütfen bu linke KESİNLİKLE tıklamayın!"
        else:
            report = f"✅ *Link Temiz Görünüyor.*\n\n"
            report += f"🔗 Taranan Link: `{url}`\n"
            report += f"📊 Sonuç: {total_scanners} güvenlik şirketi taradı, zararlı bir durum tespit edilmedi."

        return report

    except Exception as e:
        logging.error(f"VirusTotal hatası: {e}")
        return "⚠️ Link taranırken bir hata oluştu. Lütfen tekrar deneyin."

# ===================== INSTAGRAM FONKSİYONLARI =====================

def get_instagram_profile(username):
    """RapidAPI üzerinden Instagram profil bilgisi çeker."""
    if not RAPIDAPI_KEY:
        return None, "⚠️ RAPIDAPI_KEY ayarlanmamış. Lütfen Render'a ekleyin."

    url = "https://instagram360.p.rapidapi.com/userinfo"
    headers = {
        "x-rapidapi-key": RAPIDAPI_KEY,
        "x-rapidapi-host": "instagram360.p.rapidapi.com"
    }
    params = {"username_or_id": username}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=15)
        if response.status_code == 404:
            return None, f"❌ *'{username}'* adında bir Instagram hesabı bulunamadı."
        if response.status_code == 429:
            return None, "⚠️ Çok fazla istek gönderildi. Lütfen biraz bekleyip tekrar deneyin."
        response.raise_for_status()
        raw = response.json()
        # instagram360 API doğrudan veriyi döndürüyor
        data = raw.get("data", raw)
        return data, None
    except Exception as e:
        logging.error(f"Instagram API hatası: {e}")
        return None, "⚠️ Instagram bilgisi alınırken hata oluştu. Lütfen tekrar deneyin."


def format_number(n):
    """Sayıları okunabilir formata çevirir (1.2M, 45.3K gibi)."""
    if n is None:
        return "?"
    try:
        n = int(n)
        if n >= 1_000_000:
            return f"{n/1_000_000:.1f}M"
        elif n >= 1_000:
            return f"{n/1_000:.1f}K"
        return str(n)
    except:
        return str(n)

def build_profile_message(data):
    """Profil verisinden okunabilir bir mesaj oluşturur."""
    username = data.get("username", "?")
    full_name = data.get("full_name", "")
    bio = data.get("biography", "")
    followers = format_number(data.get("follower_count"))
    following = format_number(data.get("following_count"))
    posts = format_number(data.get("media_count"))
    is_private = data.get("is_private", False)
    is_verified = data.get("is_verified", False)
    profile_pic = data.get("profile_pic_url_hd") or data.get("profile_pic_url", "")
    external_url = data.get("external_url", "")

    verified_badge = " ✅" if is_verified else ""
    privacy = "🔒 Gizli Hesap" if is_private else "🌍 Açık Hesap"

    msg = f"📸 *Instagram Profil Raporu*\n"
    msg += f"━━━━━━━━━━━━━━━━━━\n"
    msg += f"👤 *Ad Soyad:* {full_name}{verified_badge}\n"
    msg += f"🔖 *Kullanıcı Adı:* @{username}\n"
    msg += f"🔐 *Hesap Türü:* {privacy}\n"
    msg += f"━━━━━━━━━━━━━━━━━━\n"
    msg += f"👥 *Takipçi:* {followers}\n"
    msg += f"➡️ *Takip Edilen:* {following}\n"
    msg += f"🖼️ *Gönderi Sayısı:* {posts}\n"
    msg += f"━━━━━━━━━━━━━━━━━━\n"
    if bio:
        msg += f"📝 *Biyografi:*\n{bio}\n"
    if external_url:
        msg += f"🔗 *Web Sitesi:* {external_url}\n"
    msg += f"\n🔍 [Profili Görüntüle](https://www.instagram.com/{username}/)"

    return msg, profile_pic

# ===================== TELEGRAM HANDLER'LARI =====================

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Bot başlatıldığında gönderilecek mesaj."""
    keyboard = [
        [InlineKeyboardButton("🔗 Link Tarama", callback_data="help_link")],
        [InlineKeyboardButton("📸 Instagram Profil Sorgula", callback_data="help_ig")],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    welcome_message = (
        "👋 Merhaba! Ben Güvenlik & Sorgulama Botuyum.\n\n"
        "🛡️ *Ne yapabilirim?*\n\n"
        "🔗 *Link Tarama:* Bana herhangi bir link gönderin, "
        "VirusTotal ile analiz edip zararlı olup olmadığını söyleyeyim.\n\n"
        "📸 *Instagram Sorgulama:* `/ig kullanici_adi` yazın, "
        "o hesabın profil bilgilerini getireyim.\n\n"
        "Aşağıdan öğrenmek istediğinizi seçin:"
    )
    await update.message.reply_text(welcome_message, parse_mode='Markdown', reply_markup=reply_markup)


async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Buton tıklamalarını işler."""
    query = update.callback_query
    await query.answer()

    if query.data == "help_link":
        await query.edit_message_text(
            "🔗 *Link Tarama Nasıl Kullanılır?*\n\n"
            "Herhangi bir linki (http:// veya https:// ile başlayan) "
            "bana mesaj olarak gönderin. Ben o linki VirusTotal veritabanında "
            "70+ güvenlik firmasına karşı analiz ederim.\n\n"
            "Örnek:\n`https://ornek-site.com`",
            parse_mode='Markdown'
        )
    elif query.data == "help_ig":
        await query.edit_message_text(
            "📸 *Instagram Sorgulama Nasıl Kullanılır?*\n\n"
            "Komutu şu şekilde kullanın:\n"
            "`/ig kullanici_adi`\n\n"
            "Örnek:\n`/ig cristiano`\n\n"
            "Size şunları gösteririm:\n"
            "• Profil fotoğrafı\n"
            "• Takipçi / Takip edilen sayısı\n"
            "• Gönderi sayısı\n"
            "• Biyografi ve web sitesi\n"
            "• Hesabın açık/gizli olduğu bilgisi",
            parse_mode='Markdown'
        )


async def instagram_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/ig komutu ile Instagram profil sorgular."""
    if not context.args:
        await update.message.reply_text(
            "📸 Kullanım: `/ig kullanici_adi`\n\nÖrnek: `/ig cristiano`",
            parse_mode='Markdown'
        )
        return

    username = context.args[0].replace("@", "").strip()

    processing_msg = await update.message.reply_text(
        f"🔍 *@{username}* hesabı sorgulanıyor...",
        parse_mode='Markdown'
    )

    try:
        # Maksimum 20 saniye bekle, sonra timeout ver
        loop = asyncio.get_event_loop()
        data, error = await asyncio.wait_for(
            loop.run_in_executor(executor, get_instagram_profile, username),
            timeout=20.0
        )
    except asyncio.TimeoutError:
        await processing_msg.edit_text(
            "⏱️ *Zaman aşımı!* Instagram API 20 saniyede cevap vermedi.\n\n"
            "Lütfen birkaç saniye bekleyip tekrar deneyin.",
            parse_mode='Markdown'
        )
        return

    if error:
        await processing_msg.edit_text(error, parse_mode='Markdown')
        return

    msg, profile_pic = build_profile_message(data)
    await processing_msg.delete()

    if profile_pic:
        try:
            await update.message.reply_photo(
                photo=profile_pic,
                caption=msg,
                parse_mode='Markdown'
            )
            return
        except Exception as e:
            logging.warning(f"Profil fotoğrafı gönderilemedi: {e}")

    await update.message.reply_text(msg, parse_mode='Markdown', disable_web_page_preview=False)


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Gelen mesajları işler - link varsa tarar."""
    text = update.message.text
    if not text:
        return

    urls = extract_urls(text)

    if not urls:
        await update.message.reply_text(
            "ℹ️ Mesajınızda taranacak bir link bulamadım.\n\n"
            "• Link taramak için `http://` veya `https://` ile başlayan bir link gönderin.\n"
            "• Instagram sorgulamak için `/ig kullanici_adi` yazın.\n"
            "• Yardım için /start yazın.",
            parse_mode='Markdown'
        )
        return

    target_url = urls[0]

    processing_msg = await update.message.reply_text(
        f"🔍 Link analiz ediliyor, lütfen bekleyin...\n`{target_url}`",
        parse_mode='Markdown'
    )

    report = check_url_virustotal(target_url)

    await processing_msg.edit_text(report, parse_mode='Markdown')


if __name__ == '__main__':
    if not TELEGRAM_BOT_TOKEN or not VIRUSTOTAL_API_KEY:
        print("======================================================")
        print("HATA: API Anahtarları Eksik!")
        print("TELEGRAM_BOT_TOKEN ve VIRUSTOTAL_API_KEY gerekli.")
        print("======================================================")
        exit()

    # Web sunucusunu arka planda başlat
    Thread(target=run_web_server, daemon=True).start()

    application = ApplicationBuilder().token(TELEGRAM_BOT_TOKEN).build()

    application.add_handler(CommandHandler('start', start))
    application.add_handler(CommandHandler('ig', instagram_command))
    application.add_handler(CallbackQueryHandler(button_callback))
    application.add_handler(MessageHandler(filters.TEXT & (~filters.COMMAND), handle_message))

    print("Bot başarıyla başlatıldı!")
    application.run_polling()
