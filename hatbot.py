#!/usr/bin/env python
#-*- coding: iso-8859-1 -*-
#  important line for string encoding

######## Python 2 !! ##########

import sys
import time
import telepot
import json
import hmac, base64, struct, hashlib, time


last_processed = 0		
last_auth_key = u""			
last_auth_attepmt = 0

def handle(msg):
	global authorized_chats
	global config
	global last_auth_key
	global last_auth_attepmt

	content_type, chat_type, chat_id, msg_date, msg_id = telepot.glance2(msg, long=True)
	chat_id_str = str(chat_id).decode('unicode-escape')

	## TODO - update chat information in config file, if chat_id changes or if chat properties change

	#print(msg)
	# if 'migrate_from_chat_id' in msg:
	# 	old_id = msg['migrate_from_chat_id']
	# 	new_id = msg['migrate_to_chat_id']
	# 	print("migrating from " + str(old_id) + " to " + str(new_id))
	# 	if old_id in config["authorized_chats"].keys():
	# 		config["authorized_chats"].remove(old_id)
	# 		config["authorized_chats"].append(new_id)

	#if ('new_chat_participant' in msg or 'left_chat_participant' in msg or 'new_chat_title' in msg) \
	#	and msg_id in config["authorized_chats"]:


	#only handle text messages	
	if content_type == 'text':
		command = msg['text']
		#replace /command@bot_name with /command
		command = command.replace("@" + config["bot_name"], "", 1)

		#ignore messages older than 3 seconds, but '/unauth' (if bot was offline)
		if (time.time() > msg_date + 3 and not command == '/unauth'):
			print("ignoring old message", chat_id, command, time.time() - msg_date)
		else:

			# if this chat is not authorized ...
			if (not config["authorized_chats"]) or config["authorized_chats"].keys().count(chat_id_str) == 0:
				# trying to authenticate
				if command.startswith("/auth "):
					# brute force protection, only one athentication attempt for every 10 seconds.
					if (last_auth_attepmt + 10 < time.time()):
						last_auth_attepmt = time.time()

						sever_key = str(get_totp_token(config["secret"])).decode('unicode-escape')
						user_key = command[6:]
						print("server: ", sever_key, "user: ", user_key)
						
						if (user_key == sever_key):
							# keys match, but key has already been used to authorize, prevent someone to authenticate with an intercepted key
							if (user_key == last_auth_key):
								print("tried to reuse key to authorize (different) chat", chat_id)
							# keys match
							else:
								last_auth_key = user_key

								# add this chat to the list of authorized chats
								chat = msg["chat"]
								config["authorized_chats"][chat_id_str] = chat
								save_changes()

								descriptor = get_description(chat)
								print(descriptor)
								
								shout('`*** WARNING ***\nnew chat has been authorized\n' + descriptor + "`")

								bot.sendMessage(chat_id, "`authorized chat`", parse_mode="Markdown", reply_markup=simple_keyboard)
					else:
						print("authentication attempt within time lock", chat_id)

				# tries to send commands but is not authorized
				else:
					#print(bool(config["authorized_chats"]), config["authorized_chats"].keys(), config["authorized_chats"].keys().count(chat_id_str))
					print("unauthorized chat", chat_id, command)
			
			#chat is authorized
			else:
				hide_keyboard = {'hide_keyboard': True}
				print(command)

				if command.startswith("/auth "):
					bot.sendMessage(chat_id, "`already authorized`", parse_mode="Markdown")
				
				# unauthorize this chat
				elif command == "/unauth":
					bot.sendMessage(chat_id, "`unauthorized chat`", parse_mode="Markdown", reply_markup=hide_keyboard)
					del config["authorized_chats"][chat_id_str]
					save_changes()

					chat = msg["chat"]
					descriptor = get_description(chat)
					print(descriptor)		
					shout('`*** WARNING ***\nchat has been unauthorized\n' + descriptor + "`")
				
				# unauthorize all chats including the current one
				elif command == "/unauth all":
					for chat_id in config["authorized_chats"].keys():
						bot.sendMessage(chat_id, "`unauthorized chat`", parse_mode="Markdown", reply_markup=hide_keyboard)
						del config["authorized_chats"][str(chat_id).decode('unicode-escape')]
					save_changes()

				# who is allowed to send commands ?
				elif command == "/who?":
					for auth_id in config["authorized_chats"].keys():
						descriptor = "`" + get_description(config["authorized_chats"][auth_id]) + "`"
						bot.sendMessage(chat_id, descriptor, parse_mode="Markdown")

				# any command relating home automation
				else:
					home_command(command, chat_id)


def get_hotp_token(secret, intervals_no):
    key = base64.b32decode(secret, True)
    msg = struct.pack(">Q", intervals_no)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = ord(h[19]) & 15
    h = (struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000
    return h

def get_totp_token(secret):
    return get_hotp_token(secret, intervals_no=int(time.time())//30)

# save changes into config file
def save_changes():
	file = open(sys.argv[1], 'w')
	json_output = json.dumps(config, indent=1)
	file.truncate()
	file.write(json_output)
	file.close()

# get a description of a group or private chat
def get_description(chat):
	descriptor = "type: " + chat["type"] + "\n"
	if chat["type"] == "group": 
		descriptor += chat["title"]
	elif chat["type"] == "private":
		username = chat["username"]
		if not username == "":
			descriptor += "@" + username + "\n"
		descriptor += chat["first_name"] + " " + chat["last_name"]
	return descriptor

# send a message to all authorized chats
def shout(message):
	if config["authorized_chats"]:
		for chat_id in config["authorized_chats"].keys():
			bot.sendMessage(chat_id, message, parse_mode="Markdown", reply_markup=simple_keyboard)

######################################## /home automation section\ ####################################
def home_command(command, chat_id):
	global last_processed
	global active_keyboard
	global ignoring

	# this the only command registered via BotFather
	if command == "/keyboard":
		bot.sendMessage(chat_id, '✏️', reply_markup=simple_keyboard)
	elif command == "/more":
		bot.sendMessage(chat_id, '`more`', parse_mode="Markdown", reply_markup=advanced_keyboard)
	elif command == "/less":
		bot.sendMessage(chat_id, '`less`', parse_mode="Markdown", reply_markup=simple_keyboard)		
	elif command == "/ignore":
		shout('`*** ignoring ***`')
		ignoring = True
	elif command == "/unignore":
		shout('`*** acknowledging ***`')
		ignoring = False
	else:
		if ignoring:
			bot.sendMessage(chat_id, "😴")
		#only allow to execute command every 1.5 seconds
		elif (last_processed + 1.5) < time.time():
			last_processed = time.time()
		
			tstring = time.strftime("%H:%M, %d.%m.%Y")

			if command == "/door":
				bot.sendMessage(chat_id, "*Tür*:              _" + tstring + "_", parse_mode="Markdown")
				# execute script
			elif command == "/garage":
				bot.sendMessage(chat_id, "*Garage*:       _" + tstring + "_", parse_mode="Markdown")  
				# execute script          
			elif command == "/light on":
				bot.sendMessage(chat_id, "💡")
				# execute script
			elif command == "/light off":
				bot.sendMessage(chat_id, "◼")
				# execute script
		else:
			bot.sendMessage(chat_id, '⌛')

advanced_keyboard = {'keyboard': [['/door', '/garage'], 
								  ['/light 1 on', '/light 2 on', '/light 3 on', '/light 4 on'],
								  ['/light 1 off', '/light 2 off', '/light 3 off', '/light 4 off'], 
								  ['/ignore', '/unignore'],
								  ['/auth', '/unauth'], 
								  ['/who?', '/unauth all'],
								  ['/less']]}
simple_keyboard = {'keyboard': [['/door', '/garage'], 
								['/light on', '/light off'], 
								['/more']]}
active_keyboard = simple_keyboard
ignoring = False

######################################## \home automation section/ ####################################


# Load bot_token, secret and authorized_chats from config file
file = open(sys.argv[1], 'r')
json_input = file.read()
config = json.loads(json_input)
file.close()

# Setting up the bot
bot = telepot.Bot(config["bot_token"])

shout('`restarted ...`')

bot.notifyOnMessage(handle)
print('Listening ...')


# Keep the program running.
while 1:
	time.sleep(10)

#create Secret
#take a 10 bytes string, do a base32 encode, get 16 Characters