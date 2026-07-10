import logging
import re
import time
import os
import asyncio
import httpx
from threading import Thread
from flask import Flask
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ApplicationBuilder, ContextTypes, CommandHandler, MessageHandler, CallbackQueryHandler, filters

# --- AYARLAR KISMI ---
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
RAPIDAPI_KEY = os.environ.get("RAPIDAPI_KEY")
# ------------------------------------------------------------------------

# Render Web Service için basit bir web sunucusu
flask_app = Flask(__name__)

@flask_app.route('/')
def home():
    return "Bot Çalışıyor!"

@flask_app.route('/healthz')
def health():
    return "OK"

def run_web_server():
    port = int(os.environ.get("PORT", 10000))
    flask_app.run(host="0.0.0.0", port=port)

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

async def check_url_virustotal(url):
    """URL'yi VirusTotal API'si ile asenkron tarar."""
    vt_url = "https://www.virustotal.com/api/v3/urls"
    headers = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY,
        "content-type": "application/x-www-form-urlencoded"
    }

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            # URL'yi gönder
            response = await client.post(vt_url, headers=headers, data={"url": url})
            response.raise_for_status()
            result_id = response.json().get('data', {}).get('id')

            if not result_id:
                return "❌ VirusTotal'den analiz ID'si alınamadı."

            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{result_id}"
            analysis_headers = {"x-apikey": VIRUSTOTAL_API_KEY}
            data_r = {}

            for _ in range(10):
                await asyncio.sleep(3)
                analysis_response = await client.get(analysis_url, headers=analysis_headers)
                analysis_response.raise_for_status()
                data_r = analysis_response.json().get('data', {})
                status = data_r.get('attributes', {}).get('status')
                if status == 'completed':
                    break

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

            report = f"🚨 *DİKKAT! TEHLİKELİ LİNK!* 🚨\n\n"
            report += f"🔗 `{url}`\n"
            report += f"📊 *{malicious + suspicious}* / {total_scanners} güvenlik şirketi zararlı buldu!\n\n"
            report += f"*Tespit Edilen Tehditler:*\n{threats_str}\n\n"
            report += "⛔ Bu linke KESİNLİKLE tıklamayın!"
        else:
            report = f"✅ *Link Temiz Görünüyor.*\n\n"
            report += f"🔗 `{url}`\n"
            report += f"📊 {total_scanners} güvenlik şirketi taradı, sorun bulunamadı."

        return report

    except httpx.TimeoutException:
        return "⏱️ VirusTotal zaman aşımına uğradı. Lütfen tekrar deneyin."
    except Exception as e:
        logging.error(f"VirusTotal hatası: {e}")
        return "⚠️ Link taranırken bir hata oluştu. Lütfen tekrar deneyin."

# ===================== INSTAGRAM FONKSİYONLARI =====================

async def get_instagram_profile(username):
    """RapidAPI üzerinden Instagram profil bilgisini asenkron çeker."""
    if not RAPIDAPI_KEY:
        return None, "⚠️ RAPIDAPI_KEY ayarlanmamış."

    url = "https://instagram360.p.rapidapi.com/userinfo"
    headers = {
        "x-rapidapi-key": RAPIDAPI_KEY,
        "x-rapidapi-host": "instagram360.p.rapidapi.com"
    }
    params = {"username_or_id": username}

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(url, headers=headers, params=params)

        if response.status_code == 404:
            return None, f"❌ *'{username}'* adında bir Instagram hesabı bulunamadı."
        if response.status_code == 403:
            return None, "⚠️ API erişim hatası. RAPIDAPI_KEY'i kontrol edin."
        if response.status_code == 429:
            return None, "⚠️ Çok fazla istek. Lütfen bekleyip tekrar deneyin."
        response.raise_for_status()

        raw = response.json()
        logging.info(f"Instagram API yanıtı: {str(raw)[:300]}")
        data = raw.get("data", raw)
        return data, None

    except httpx.TimeoutException:
        return None, "⏱️ Instagram API 15 saniyede cevap vermedi. Tekrar deneyin."
    except Exception as e:
        logging.error(f"Instagram API hatası: {e}")
        return None, f"⚠️ Hata oluştu: {str(e)[:100]}"


def format_number(n):
    """Sayıları okunabilir formata çevirir."""
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
    full_name = data.get("full_name", "") or data.get("fullname", "")
    bio = data.get("biography", "") or data.get("bio", "")
    followers = format_number(data.get("follower_count") or data.get("followers"))
    following = format_number(data.get("following_count") or data.get("following"))
    posts = format_number(data.get("media_count") or data.get("posts"))
    is_private = data.get("is_private", False)
    is_verified = data.get("is_verified", False)
    profile_pic = data.get("profile_pic_url_hd") or data.get("profile_pic_url") or data.get("profile_picture", "")
    external_url = data.get("external_url", "") or data.get("website", "")

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
    keyboard = [
        [InlineKeyboardButton("🔗 Link Tarama", callback_data="help_link")],
        [InlineKeyboardButton("📸 Instagram Sorgula", callback_data="help_ig")],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    welcome_message = (
        "👋 Merhaba! Ben Güvenlik & Sorgulama Botuyum.\n\n"
        "🛡️ *Neler yapabilirim?*\n\n"
        "🔗 *Link Tarama:* Bir link gönderin, VirusTotal ile analiz edeyim.\n\n"
        "📸 *Instagram Sorgulama:* `/ig kullanici_adi` yazın, profil bilgilerini getireyim.\n\n"
        "Aşağıdan seçim yapın:"
    )
    await update.message.reply_text(welcome_message, parse_mode='Markdown', reply_markup=reply_markup)


async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    if query.data == "help_link":
        await query.edit_message_text(
            "🔗 *Link Tarama:*\n\nHerhangi bir linki doğrudan mesaj olarak gönderin.\nÖrnek:\n`https://ornek-site.com`",
            parse_mode='Markdown'
        )
    elif query.data == "help_ig":
        await query.edit_message_text(
            "📸 *Instagram Sorgulama:*\n\nKomut: `/ig kullanici_adi`\nÖrnek: `/ig cristiano`\n\nSize şunları gösteririm:\n• Profil fotoğrafı\n• Takipçi / Takip edilen\n• Gönderi sayısı\n• Biyografi",
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
        f"🔍 *@{username}* sorgulanıyor...",
        parse_mode='Markdown'
    )

    data, error = await get_instagram_profile(username)

    if error:
        await processing_msg.edit_text(error, parse_mode='Markdown')
        return

    msg, profile_pic = build_profile_message(data)
    await processing_msg.delete()

    if profile_pic:
        try:
            await update.message.reply_photo(photo=profile_pic, caption=msg, parse_mode='Markdown')
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
            "• Link taramak için `http://` veya `https://` ile başlayan link gönderin.\n"
            "• Instagram için `/ig kullanici_adi` yazın.\n"
            "• Yardım için /start yazın.",
            parse_mode='Markdown'
        )
        return

    target_url = urls[0]
    processing_msg = await update.message.reply_text(
        f"🔍 Link analiz ediliyor...\n`{target_url}`",
        parse_mode='Markdown'
    )

    report = await check_url_virustotal(target_url)
    await processing_msg.edit_text(report, parse_mode='Markdown')


if __name__ == '__main__':
    if not TELEGRAM_BOT_TOKEN or not VIRUSTOTAL_API_KEY:
        print("HATA: TELEGRAM_BOT_TOKEN ve VIRUSTOTAL_API_KEY gerekli!")
        exit()

    Thread(target=run_web_server, daemon=True).start()

    application = ApplicationBuilder().token(TELEGRAM_BOT_TOKEN).build()
    application.add_handler(CommandHandler('start', start))
    application.add_handler(CommandHandler('ig', instagram_command))
    application.add_handler(CallbackQueryHandler(button_callback))
    application.add_handler(MessageHandler(filters.TEXT & (~filters.COMMAND), handle_message))

    print("Bot başarıyla başlatıldı!")
    application.run_polling()
