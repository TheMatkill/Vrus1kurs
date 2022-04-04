import requests
import telebot
import json
import time
import ast
import os 
import shutil
import markdown


token = 'Токен телеграмм бота' #Telegram 
api = 'x-apikey: 4d0be5ab6e31f396bab19c5158ec0cf2994ec9afbca27dca615941fa8d77d402' #VirusTotal api token
url_scan = 'https://www.virustotal.com/api/v3/files' 
url_info = 'https://www.virustotal.com/api/v3/analyses/' 
markdown = """
    *bold text*
    _italic text_
    [text](URL)
    """

bot = telebot.TeleBot(token)
max_file_size = int('33554430')

@bot.message_handler(commands=['start'])
def start_message(message):
    name = message.from_user.first_name
#Отправка клавиатуры
    use_markup = telebot.types.ReplyKeyboardMarkup(True)
    use_markup.row('Помощь', 'Автор',"FAQ")
#Отправка приветствия
    bot.send_message(message.chat.id, "Привет👋 "+ (name)
        + "\nОтправь файл для его проверки ", reply_markup = use_markup)
    
@bot.message_handler(content_types=['document'])
def handle_scans_files(message):
    if message.document.file_size > max_file_size:
        bot.send_message(message.chat.id, "Извините файл слишком большой")
    else:
        global file_name
        global message_r
        global msg
        message_r = message.chat.id
        file_name = message.document.file_name
        chat_id = message.chat.id
        file_info = bot.get_file(message.document.file_id)
        file_size = message.document.file_size
        msg = bot.reply_to(message, "Пожалуйста ожидайте!\nСреднее время ответа: 3 минуты")
        downloaded_file = bot.download_file(file_info.file_path)
        src = 'C:/Users/User/Desktop/Fileantivirus/' + message.document.file_name
        with open(src, 'wb') as new_file:
                new_file.write(downloaded_file)
        sendVT()

def sendVT():
    src = 'C:/Users/User/Desktop/Fileantivirus/' + file_name
    api_url = 'https://www.virustotal.com/api/v3/files'
    headers = {'x-apikey' : '4d0be5ab6e31f396bab19c5158ec0cf2994ec9afbca27dca615941fa8d77d402'}
    with open(src, 'rb') as file:
        files = {'file': (src, file)}
        response = requests.post(api_url, headers=headers, files=files)
        resource = response.json()["data"]["id"]
        print(resource)
        type = (response.json()["data"]["type"])
        if type == "analysis":
            bot.edit_message_text("✅Файл отправлен на проверку\nСреднее время ответа: 3-5 минут", chat_id=message_r, message_id=msg.message_id)
        else:
            bot.edit_message_text("⛔️Файл не удалось отправить", chat_id=message_r, message_id=msg.message_id)

    while True:
        pass
        url = "https://www.virustotal.com/api/v3/analyses/" + (response.json()["data"]["id"])
        headers = {
        "Accept": "application/json",
        "x-apikey": "4d0be5ab6e31f396bab19c5158ec0cf2994ec9afbca27dca615941fa8d77d402"
        }
        response = requests.request("GET", url, headers=headers)
        resource = response.json()
        res = (response.json()["data"]["attributes"]["stats"]["undetected"])
        print (res)
        if res > 1 :
         break
    
    
    virus_false = (response.json()["data"]["attributes"]["stats"]["undetected"])
    virus_tr = (response.json()["data"]["attributes"]["stats"]["malicious"]) + (response.json()["data"]["attributes"]["stats"]["suspicious"])
    markup = telebot.types.InlineKeyboardMarkup()
    markup.add(telebot.types.InlineKeyboardButton(text='Детали', callback_data=1))
    bot.edit_message_text(("🧬Обнаружений: " )+ str(virus_tr)+"/"+str(virus_false), chat_id=message_r, message_id=msg.message_id, reply_markup=markup)
    global av_data
    av_data = (response.json()['data']['attributes']['results'])
    os.remove('C:/Users/User/Desktop/Fileantivirus/' + file_name)
    
#Нажатие на кнопку подробности
@bot.callback_query_handler(func=lambda call: True)
def query_handler(call):
    if call.data == '1':
        response = "Результаты:\n"
        for engine in av_data:        
            if av_data[engine]['category'] == 'malicious' or av_data[engine]['category'] == 'suspicious':
                response = response + f"❌ {av_data[engine]['engine_name']}: {av_data[engine]['result']}\n"

        for engine in av_data:
            if av_data[engine]['category'] == 'undetected':
                response = response + f"✅ {av_data[engine]['engine_name']}\n"

        for engine in av_data:        
            if av_data[engine]['category'] == 'malicious' or av_data[engine]['category'] == 'suspicious':
                response = response + f"❌ {av_data[engine]['engine_name']}: {av_data[engine]['result']}\n"

            bot.edit_message_text((response), chat_id=message_r, message_id=msg.message_id)
            
            break
    answer = '0'
    if call.data == '3':
        answer = '_VirusTotal будет сканировать и обнаруживать, при необходимости, любой тип двоичного содержимого, будь то исполняемый файл Windows, Android APK, PDF-файлы, код javascript и т. д. Большинство антивирусных компаний, участвующих в VirusTotal, будут иметь решения для нескольких платформ, поэтому они обычно создают сигнатуры обнаружения для любого вредоносного контента_'
        bot.send_message(call.message.chat.id, answer, parse_mode="markdown")
        bot.edit_message_reply_markup(call.message.chat.id, call.message.message_id)
    elif call.data == '4':
        answer = '_Сервис VirusTotal был разработан не как инструмент для проведения сравнительного анализа антивирусов, а как инструмент, который проверяет подозрительные образцы с помощью нескольких антивирусных решений и помогает антивирусным лабораториям, пересылая им вредоносное ПО, которое они не могут обнаружить. Те, кто использует VirusTotal для сравнительного анализа антивирусов, должны знать, что они делают много неявных ошибок в своей методологии, наиболее очевидными из которых являются:\n\n~Антивирусные ядра VirusTotal являются версиями командной строки, поэтому в зависимости от продукта они не будут вести себя точно так же, как версии для настольных компьютеров: например, решения для настольных компьютеров могут использовать методы, основанные на поведенческом анализе и учете с персональными брандмауэрами, которые могут уменьшить точки входа и смягчить распространение и т.д.\n\n~В VirusTotal решения, ориентированные на рабочий стол, сосуществуют с решениями, ориентированными на периметр; эвристика в этой последней группе может быть более агрессивной и параноидальной, поскольку влияние ложных срабатываний менее заметно в периметре. Просто некорректно сравнивать обе группы.\n\n~Некоторые из решений, включенных в VirusTotal, параметризованы (в соответствии с желанием компании-разработчика) с другим уровнем эвристики/агрессивности, чем официальная конфигурация по умолчанию для конечного пользователя._'
        bot.send_message(call.message.chat.id, answer, parse_mode="markdown")
        bot.edit_message_reply_markup(call.message.chat.id, call.message.message_id)
    elif call.data == '5':
        answer = '_Иногда антивирусные решения VirusTotal отличаются от общедоступных коммерческих версий. Очень часто антивирусные компании параметризуют свои движки специально для VirusTotal (усиленная эвристика, взаимодействие с облаком, включение бета-сигнатур и т. д.). Поэтому иногда антивирусное решение в VirusTotal не будет вести себя точно так же, как эквивалентная общедоступная коммерческая версия данного продукта._'
        bot.send_message(call.message.chat.id, answer, parse_mode="markdown")
        bot.edit_message_reply_markup(call.message.chat.id, call.message.message_id)
   
@bot.message_handler(content_types=['photo'])
def filterphoto(message):
    bot.send_message(message.chat.id, "Бот не может проверить фотографию, пожалуйста отправьте файл")

#Отработка кнопок
@bot.message_handler(content_types='text')
def message_reply(message):
    global messageID
    messageID = message.chat.id
    if message.text=="Помощь":
        bot.send_message(message.chat.id,"*Бот основан на*"" [VirusTotal](https://www.virustotal.com/)\n\n""_• Вы можете отправить файл боту или переслать его с другого канала или с личного диалога, и он проверит файл на VirusTotal с помощью более 70 различных антивирусов.\n\n• Для получения результатов сканирования, отправьте мне любой файл размером до 32 МБ, и вы получите подробный его анализ.\n\n• С помощью бота вы можете осуществлять анализ подозрительных файлов на предмет выявления вредоносных программ.\n\nБот ещё будет дорабатываться и совершенствоваться!_", parse_mode="markdown")
    if message.text=="Автор":
        bot.send_message(message.chat.id,'Автор: @CryptoFlatz')
    if message.text=="FAQ":
        sendFAQ()

@bot.message_handler(content_types='text')
def sendFAQ():
    markup = telebot.types.InlineKeyboardMarkup()
    markup.add(telebot.types.InlineKeyboardButton(text='Какие файлы будет проверять VirusTotal?', callback_data=3))
    markup.add(telebot.types.InlineKeyboardButton(text='Почему нету статистики сравнения антивирусов?', callback_data=4))
    markup.add(telebot.types.InlineKeyboardButton(text='VirusTotal обнаруживает файл, а мой ПК - нет.', callback_data=5))
    bot.send_message(messageID, "*Раздел часто задаваемых вопросов\nВыберите вопрос который вас интересует*", parse_mode="markdown", reply_markup=markup)

bot.polling()
