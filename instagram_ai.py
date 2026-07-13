import os
import time
import logging
from threading import Thread
from instagrapi import Client
from groq import Groq

log = logging.getLogger(__name__)

# Ayarlar
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
IG_USER = os.environ.get("IG_USERNAME", "")
IG_PASS = os.environ.get("IG_PASSWORD", "")

cl = Client()
groq_client = Groq(api_key=GROQ_API_KEY) if GROQ_API_KEY else None
ig_active = False
ig_login_error = "Henüz denenmedi."

# Son kontrol edilen mesajların ID'lerini tutalım ki aynı mesaja iki kez cevap atmayalım
seen_messages = set()

def init_instagram():
    global ig_active, ig_login_error
    if not IG_USER or not IG_PASS:
        ig_login_error = "IG_USERNAME veya IG_PASSWORD eksik."
        log.warning(ig_login_error)
        return False
        
    try:
        log.info(f"Instagram'a {IG_USER} olarak giriş yapılıyor...")
        cl.login(IG_USER, IG_PASS)
        ig_active = True
        ig_login_error = ""
        log.info("Instagram girişi başarılı!")
        return True
    except Exception as e:
        ig_login_error = str(e)
        log.error(f"Instagram giriş hatası: {e}")
        return False

def generate_ai_reply(user_message: str) -> str:
    if not groq_client:
        return "Yapay zeka (Groq) API anahtarı eksik."
        
    try:
        chat_completion = groq_client.chat.completions.create(
            messages=[
                {
                    "role": "system",
                    "content": "Sen sosyal medyada kibar ve yardımcı bir asistansın. Sana yazan takipçilere kısa, samimi ve Türkçe cevaplar ver. Emolojiler kullan."
                },
                {
                    "role": "user",
                    "content": user_message,
                }
            ],
            model="llama3-8b-8192",
            temperature=0.7,
            max_tokens=150
        )
        return chat_completion.choices[0].message.content
    except Exception as e:
        log.error(f"Groq AI Hatası: {e}")
        return "Üzgünüm, şu an bağlantımda bir sorun var."

def check_dms_loop(telegram_bot, admin_chat_id):
    if not ig_active:
        return
        
    log.info("Instagram DM dinleyicisi başlatıldı...")
    while True:
        try:
            # En son 5 DM kutusunu kontrol et
            threads = cl.direct_threads(5)
            for thread in threads:
                last_msg = thread.messages[0]
                
                # Eğer mesaj bizden gelmiyorsa ve daha önce görmediysek
                if str(last_msg.user_id) != str(cl.user_id) and last_msg.id not in seen_messages:
                    seen_messages.add(last_msg.id)
                    
                    sender_name = thread.users[0].username
                    msg_text = last_msg.text
                    
                    if msg_text:
                        log.info(f"Yeni IG DM -> {sender_name}: {msg_text}")
                        
                        # Telegram'a Bildirim Gönder
                        if admin_chat_id:
                            telegram_bot.send_message(
                                chat_id=admin_chat_id, 
                                text=f"📩 <b>Instagram DM!</b>\n👤 @{sender_name}: <i>{msg_text}</i>\n🤖 AI cevap düşünüyor...",
                                parse_mode="HTML"
                            )
                        
                        # Yapay zekaya sor
                        ai_reply = generate_ai_reply(msg_text)
                        
                        # Instagram'dan Cevap At
                        cl.direct_send(ai_reply, thread_ids=[thread.id])
                        
                        # Telegram'a Bildir
                        if admin_chat_id:
                            telegram_bot.send_message(
                                chat_id=admin_chat_id, 
                                text=f"✅ <b>AI Cevap Verdi:</b>\n<i>{ai_reply}</i>",
                                parse_mode="HTML"
                            )
                            
        except Exception as e:
            log.error(f"DM kontrol hatası: {e}")
            
        # Instagram'ın bizi banlamaması için döngüde en az 60 saniye beklemeliyiz.
        time.sleep(60)

def start_ig_listener(telegram_bot, admin_chat_id):
    if init_instagram():
        Thread(target=check_dms_loop, args=(telegram_bot, admin_chat_id), daemon=True).start()

def ig_send_message(username: str, text: str):
    if not ig_active:
        return f"⚠️ Instagram hesabı aktif değil.\n🛑 <b>Hata:</b> {ig_login_error}"
    try:
        user_id = cl.user_id_from_username(username)
        cl.direct_send(text, user_ids=[user_id])
        return f"✅ @{username} kullanıcısına mesaj gönderildi!"
    except Exception as e:
        return f"❌ Mesaj gönderilemedi: {e}"

def ig_get_followers(username: str):
    if not ig_active:
        return f"⚠️ Instagram hesabı aktif değil.\n🛑 <b>Hata:</b> {ig_login_error}"
    try:
        user_id = cl.user_id_from_username(username)
        followers = cl.user_followers(user_id, amount=20) # Çok çekmek ban riskini artırır, ilk 20'yi alıyoruz
        follower_list = [f"@{f.username}" for f in followers.values()]
        return follower_list
    except Exception as e:
        return f"❌ Takipçiler çekilemedi: {e}"
