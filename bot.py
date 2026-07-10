import logging
import re
import requests
import time
import os
from threading import Thread
from flask import Flask
from telegram import Update
from telegram.ext import ApplicationBuilder, ContextTypes, CommandHandler, MessageHandler, filters

# --- AYARLAR KISMI ---
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
# ------------------------------------------------------------------------

# Render Web Service için basit bir web sunucusu (Botun kapanmasını engeller)
app = Flask(__name__)
@app.route('/')
def home():
    return "Bot Çalışıyor!"

def run_web_server():
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)

# Log ayarları (Hataları konsolda görmek için)
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

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
        # Önce URL'yi taraması için gönder
        response = requests.post(vt_url, headers=headers, data=data)
        response.raise_for_status()
        result_id = response.json().get('data', {}).get('id')
        
        if not result_id:
            return "❌ VirusTotal'den analiz ID'si alınamadı."

        # Analiz sonucunu çek (Bitmesini bekleyerek)
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{result_id}"
        
        for _ in range(10): # Maksimum 30 saniye bekle
            analysis_response = requests.get(analysis_url, headers={"x-apikey": VIRUSTOTAL_API_KEY})
            analysis_response.raise_for_status()
            
            data = analysis_response.json().get('data', {})
            status = data.get('attributes', {}).get('status')
            
            if status == 'completed':
                break
            
            time.sleep(3) # 3 saniye bekle ve tekrar kontrol et
            
        stats = data.get('attributes', {}).get('stats', {})
        results = data.get('attributes', {}).get('results', {})
        
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
                    threats.append(f"- {engine}: {threat_name}")
            
            # Sadece ilk 5 tehdidi göster kalabalık olmasın
            threats_str = "\n".join(threats[:5])
            if len(threats) > 5:
                threats_str += f"\n...ve {len(threats)-5} şirket daha."
            
            report = f"🚨 **DİKKAT! TEHLİKELİ LİNK TESPİT EDİLDİ!** 🚨\n\n"
            report += f"Taranan Link: {url}\n"
            report += f"Sonuç: {total_scanners} güvenlik şirketinden **{malicious + suspicious}** tanesi zararlı/şüpheli buldu!\n\n"
            report += f"**Tespit Edilen Bazı Tehditler:**\n{threats_str}\n\n"
            report += "Lütfen bu linke KESİNLİKLE tıklamayın!"
        else:
            report = f"✅ **Link Temiz Görünüyor.**\n\n"
            report += f"Taranan Link: {url}\n"
            report += f"Sonuç: {total_scanners} güvenlik şirketi taradı, zararlı bir durum tespit edilmedi."
            
        return report

    except Exception as e:
        logging.error(f"VirusTotal hatası: {e}")
        return "⚠️ Link taranırken bir hata oluştu. Lütfen tekrar deneyin."

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Bot başlatıldığında gönderilecek mesaj."""
    welcome_message = (
        "Merhaba! Ben Güvenlik Botuyum. 🛡️\n\n"
        "Bana şüpheli bulduğunuz herhangi bir linki gönderin, "
        "içinde virüs, kimlik avı (phishing) veya zararlı yazılım olup olmadığını "
        "VirusTotal veri tabanından saniyeler içinde analiz edip size söyleyeyim."
    )
    await context.bot.send_message(chat_id=update.effective_chat.id, text=welcome_message)

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Gelen mesajları işler ve link varsa tarar."""
    text = update.message.text
    if not text:
        return

    urls = extract_urls(text)
    
    if not urls:
        await context.bot.send_message(chat_id=update.effective_chat.id, text="Mesajınızda taranacak bir link bulamadım. Lütfen 'http://' veya 'https://' içeren bir link gönderin.")
        return

    # Sadece ilk linki tarayalım
    target_url = urls[0]
    
    # Kullanıcıya tarandığını bildirelim
    processing_msg = await context.bot.send_message(
        chat_id=update.effective_chat.id, 
        text=f"🔍 '{target_url}' linki analiz ediliyor. Lütfen bekleyin..."
    )
    
    # Taramayı yap
    report = check_url_virustotal(target_url)
    
    # Sonucu düzenle ve gönder
    await context.bot.edit_message_text(
        chat_id=update.effective_chat.id,
        message_id=processing_msg.message_id,
        text=report,
        parse_mode='Markdown'
    )

if __name__ == '__main__':
    if not TELEGRAM_BOT_TOKEN or not VIRUSTOTAL_API_KEY:
        print("======================================================")
        print("HATA: API Anahtarları Eksik!")
        print("Lütfen Environment Variables (Ortam Değişkenleri) ayarlarını yapın.")
        print("======================================================")
        exit()

    # Web sunucusunu arka planda başlat
    Thread(target=run_web_server).start()

    application = ApplicationBuilder().token(TELEGRAM_BOT_TOKEN).build()
    
    start_handler = CommandHandler('start', start)
    message_handler = MessageHandler(filters.TEXT & (~filters.COMMAND), handle_message)
    
    application.add_handler(start_handler)
    application.add_handler(message_handler)
    
    print("Bot başarıyla başlatıldı! Telegram'a gidip bota mesaj atabilirsiniz...")
    application.run_polling()
