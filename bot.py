from pyrogram import Client, filters

# Replace with your actual API ID, API HASH, and Bot Token
API_ID = YOUR_API_ID
API_HASH = "YOUR_API_HASH"
BOT_TOKEN = "telegram"

# Create a Pyrogram client instance
app = Client("my_hey_bot", api_id=API_ID, api_hash=API_HASH, bot_token=BOT_TOKEN)

# Define a message handler for "hey"
@app.on_message(filters.text & filters.lower & filters.private & filters.regex("hey"))
async def say_hi(client, message):
    """
    Responds with 'Hi!' when someone sends 'hey' in a private chat.
    """
    await message.reply("Hi!")

# Start the bot
print("Bot is starting...")
app.run()
print("Bot has stopped.")
