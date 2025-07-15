import asyncio
import base64
import re
import random
import requests
import string
import json
from datetime import datetime, timedelta
from urllib.parse import unquote, urlparse, parse_qs
from pyrogram import Client as PyrogramClient, enums

# --- Configuration Variables ---
TELEGRAM_API_ID = 1234567 # Replace with your Telegram API ID
TELEGRAM_API_HASH = "your_api_hash_here" # Replace with your Telegram API Hash
TELEGRAM_SESSION_NAME = "telegram" # Name for your Pyrogram session file
OUTPUT_FILE = "configs.txt" # Local file to save configurations
FORMAT_STRING = "Config | {number} / {total}" # Format for the config name


# --- Protocol Patterns for Extraction ---
PATTERNS = [
    # VMess (base64 encoded)
    re.compile(r"vmess://[a-zA-Z0-9+/=]+"),

    # VLESS (more comprehensive pattern)
    re.compile(r"vless://[^ \n\"]+"),

    # Shadowsocks (supports all formats):
    re.compile(r"ss://[a-zA-Z0-9\-_=.@:+/#?&%]+(?=[ \n\"]|$)"),

    # Trojan (more comprehensive pattern)
    re.compile(r"trojan://[^ \n\"]+")
]

# --- Helper Functions ---

def random_string(length=6):
    """Generates a random alphanumeric string."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def extract_country_info(old_fragment):
    """
    Extracts country flag and name from an old config fragment.
    Prioritizes flag, then country name.
    """
    flag_map = {
        "🇩🇪": "Germany", "🇫🇷": "France", "🇹🇷": "Turkey", "🇦🇲": "Armenia",
        "🇦🇪": "UAE", "🇬🇧": "UK", "🇮🇹": "Italy", "🇺🇸": "USA",
        "🇨🇦": "Canada", "🇮🇷": "Iran", "🇸🇬": "Singapore", "🇯🇵": "Japan",
        "🇰🇷": "Korea", "🇷🇺": "Russia", "🇨🇳": "China", "🇧🇷": "Brazil",
        "🇮🇳": "India", "🇿🇦": "South Africa", "🇦🇺": "Australia",
        # Add more mappings as needed
    }

    for flag, country in flag_map.items():
        if flag in old_fragment:
            return flag, country

    for country in flag_map.values():
        if country.lower() in old_fragment.lower():
            # Find the corresponding flag for the found country name
            flag = next((f for f, c in flag_map.items() if c.lower() == country.lower()), "🌐")
            return flag, country

    return "🌐", "International"

def format_configs(configs):
    """
    Formats a list of configuration URLs by adding dynamic fragments (names).
    """
    now = datetime.now()
    total = len(configs)
    formatted = []

    for i, config in enumerate(configs):
        if not config.strip():
            continue

        # Split the config from its existing fragment (if any)
        parts = config.split('#', 1)
        url_part = parts[0]
        old_fragment = unquote(parts[1]) if len(parts) > 1 else ""

        flag_emoji, country_name = extract_country_info(old_fragment)

        replacements = {
            '{number}': str(i+1),
            '{total}': str(total),
            '{old}': old_fragment,
            '{country}': country_name,
            '{flag}': flag_emoji,
            '{random}': random_string(),
            '{date}': now.strftime("%Y-%m-%d"),
            '{time}': now.strftime("%H:%M:%S")
        }

        # Apply replacements to the FORMAT_STRING
        new_fragment = FORMAT_STRING
        for placeholder, value in replacements.items():
            new_fragment = new_fragment.replace(placeholder, value)

        formatted.append(f"{url_part}#{new_fragment}")

    return formatted

def parse_config_for_deduplication(config_url):
    """
    Parses a V2Ray/Shadowsocks/Trojan config URL to extract unique identifying features.
    Returns a tuple of identifying features for comparison.
    Returns None if parsing fails or the config is malformed for deduplication.
    This function is crucial for "smart" duplicate checking.
    """
    try: # Outer try block for general parsing errors
        if config_url.startswith("vmess://"):
            encoded_json = config_url[len("vmess://"):]
            # Ensure proper base64 padding before decoding
            missing_padding = len(encoded_json) % 4
            if missing_padding:
                encoded_json += '=' * (4 - missing_padding)
            decoded_json = base64.b64decode(encoded_json).decode('utf-8')
            data = json.loads(decoded_json)
            # Core identifying features for VMess: address, port, user ID (id)
            # Use .get() with None default to avoid KeyError if a field is missing
            return ("vmess", data.get("add"), data.get("port"), data.get("id"))

        elif config_url.startswith("vless://") or config_url.startswith("trojan://"):
            parsed = urlparse(config_url)
            protocol = parsed.scheme
            user_info = parsed.username # For VLESS it's UUID, for Trojan it's password
            host = parsed.hostname
            port = parsed.port
            query_params = parse_qs(parsed.query)

            # Common parameters that impact uniqueness for VLESS/Trojan
            type_param = query_params.get('type', [''])[0]
            security_param = query_params.get('security', [''])[0] # e.g., 'tls'
            sni_param = query_params.get('sni', [''])[0] # SNI can be important for server identification
            fp_param = query_params.get('fp', [''])[0] # Fingerprint (e.g., chrome, firefox)

            # Construct the identifier tuple based on protocol
            if protocol == "vless":
                # Order matters in the tuple for consistent comparison
                return (protocol, user_info, host, port, type_param, security_param, sni_param, fp_param)
            elif protocol == "trojan":
                # Order matters in the tuple for consistent comparison
                return (protocol, user_info, host, port, security_param, sni_param)
            # No 'else' needed here, as the outer try-except will catch if something unexpected happens

        elif config_url.startswith("ss://"):
            # Shadowsocks can have various formats, including base64 encoding
            # We need to handle both direct and base64 encoded parts
            # ss://method:password@host:port#tag
            # ss://base64encoded_all_including_credentials_and_address#tag
            pure_ss_url = config_url[len("ss://"):].split('#', 1)[0]

            if '@' in pure_ss_url:
                # Format: method:password@host:port OR base64(method:password)@host:port
                auth_part, addr_port_part = pure_ss_url.split('@')

                method = None
                password = None

                try: # Inner try for auth_part parsing
                    if ':' in auth_part: # Standard method:password
                        method, password = auth_part.split(':', 1)
                    else: # Base64 encoded method:password
                        decoded_auth = base64.b64decode(auth_part + '==').decode('utf-8')
                        if ':' in decoded_auth:
                            method, password = decoded_auth.split(':', 1)
                except Exception:
                    pass # Failed to decode or parse auth part, method/password remain None

                try: # Inner try for address:port parsing
                    host, port_str = addr_port_part.split(':')
                    port = int(port_str)
                    return ("ss", method, password, host, port)
                except Exception:
                    return None # Failed to parse host/port
            else:
                # Assume it's a fully base64 encoded string
                try: # Inner try for full base64 string decoding
                    decoded_entire_string = base64.b64decode(pure_ss_url + '==').decode('utf-8')
                    # Now it should be method:password@host:port
                    if '@' in decoded_entire_string:
                        auth_part, addr_port_part = decoded_entire_string.split('@')
                        method, password = auth_part.split(':', 1) # Assuming method:password is not base64 encoded here
                        host, port_str = addr_port_part.split(':')
                        port = int(port_str)
                        return ("ss", method, password, host, port)
                    else:
                        return None # Malformed fully base64 encoded SS
                except Exception:
                    return None # Failed to decode entire SS string

        # If none of the 'if' conditions for protocols matched,
        # then the config is unrecognized or unparsable.
        return None # This 'return None' is now correctly placed within the outer 'try' block

    except Exception as e:
        # print(f"DEBUG: Critical error parsing config '{config_url[:80]}...': {e}") # Uncomment for deeper debugging
        return None # Return None if any general parsing error occurs


# --- Main Logic Functions ---

async def scan_channels(client):
    """
    Scans Telegram channels for V2Ray/SS/Trojan configurations.
    Uses an identifier-based deduplication for robustness.
    """
    unique_identifiers = set() # Stores tuples of identifying features
    found_configs = []         # Stores the original, full config strings (unique by identifier)

    cutoff = datetime.utcnow() - timedelta(hours=24) # Scan messages from the last 24 hours

    async for dialog in client.get_dialogs():
        # Check if it's a channel and if there's a recent message
        if not (dialog.chat.type == enums.ChatType.CHANNEL and
                dialog.top_message and
                dialog.top_message.date >= cutoff):
            continue

        print(f"Scanning: {dialog.chat.title}")
        try:
            # Iterate through messages from newest to oldest
            async for msg in client.get_chat_history(dialog.chat.id):
                if msg.date < cutoff: # Stop if messages are older than cutoff
                    break
                if text := msg.text or msg.caption:
                    for pattern in PATTERNS:
                        for match in pattern.finditer(text):
                            config = match.group(0).strip()
                            # Basic validation to ensure it's a plausible config (e.g., contains common URL chars)
                            if any(x in config for x in ['@', '.', ':', '//']):
                                identifier = parse_config_for_deduplication(config)
                                if identifier and identifier not in unique_identifiers:
                                    unique_identifiers.add(identifier)
                                    found_configs.append(config)
        except Exception as e:
            print(f"Error in {dialog.chat.title}: {str(e)[:50]}...") # Print a truncated error message

    return found_configs # Return the list of original, unique config strings

async def telegram_scan():
    """
    Orchestrates the Telegram scanning process.
    Initializes Pyrogram client, scans channels, formats, and saves configs.
    """
    # Initialize Pyrogram client
    async with PyrogramClient(TELEGRAM_SESSION_NAME, TELEGRAM_API_ID, TELEGRAM_API_HASH) as client:
        print("Starting Telegram scan...")
        # configs will be a list of original config strings, already de-duplicated by identifier
        configs = await scan_channels(client)

        if not configs:
            print("\n❌ No configurations found in Telegram!")
            return None

        print(f"\nFound {len(configs)} unique configurations (by identifier) from Telegram messages.")

        # Format the configs (add new fragment names)
        formatted_configs = format_configs(list(configs))

        # Create output text
        output_text = "\n".join(formatted_configs)

        # Save to file
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:            f.write(output_text)

        print(f"\n✅ Processed {len(formatted_configs)} configurations and saved to: {OUTPUT_FILE}")

        return OUTPUT_FILE

async def upload_to_github(file_path):
    """
    Uploads the content of a local file to a specified GitHub repository.
    Handles existing files by updating them.
    """
    if not file_path:
        print("No file to upload to GitHub.")
        return

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content_to_upload = f.read()
    except FileNotFoundError:
        print(f"Error: Output file '{file_path}' not found for GitHub upload.")
        return

    # Encode the content to base64
    encoded_content = base64.b64encode(content_to_upload.encode('utf-8')).decode('utf-8')



# --- Main Execution ---

async def main():
    """
    Main asynchronous function to run the entire process:
    1. Scan Telegram channels.
    2. Perform final deduplication on the saved file.
    3. Upload to GitHub.
    """
    # 1. Scan Telegram and save results to a local file
    output_file_path = await telegram_scan()

    if output_file_path:
        print("\nPerforming final duplicate check based on server identifiers...")
        try:
            with open(output_file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            # Remove empty lines and strip whitespace for consistent processing
            clean_lines = [line.strip() for line in lines if line.strip()]

            unique_identifiers_final = set() # To store parsed identifier tuples
            final_unique_configs = []        # To store the original unique config strings

            initial_count = len(clean_lines)
            duplicates_found_in_final_check = 0

            for line in clean_lines:
                identifier = parse_config_for_deduplication(line)
                if identifier: # Only proceed if the identifier was successfully parsed
                    if identifier not in unique_identifiers_final:
                        unique_identifiers_final.add(identifier)
                        final_unique_configs.append(line)
                    else:
                        duplicates_found_in_final_check += 1
                else:
                    # If a line couldn't be parsed, it's either malformed or not a recognized config.
                    # We'll include it in the final list for now, but it won't be deduplicated by identifier.
                    # Consider logging these if they're unexpected.
                    # print(f"WARNING: Could not parse config for deduplication: {line[:80]}...")
                    final_unique_configs.append(line)

            if duplicates_found_in_final_check > 0:
                print(f"🚨 Final check found and removed {duplicates_found_in_final_check} duplicate entries based on server identifiers.")
                # Rewrite the file with the truly unique configurations
                with open(output_file_path, "w", encoding="utf-8") as f:
                    for config in final_unique_configs:
                        f.write(config + "\n")
                print(f"Updated '{output_file_path}' with {len(final_unique_configs)} truly unique configurations.")
            else:
                print("No additional duplicates found after final server identifier check.")

        except FileNotFoundError:
            print(f"Error: Output file '{output_file_path}' not found for final duplicate check. This should not happen after telegram_scan.")
        except Exception as e:
            print(f"An unexpected error occurred during the final server identifier duplicate check: {e}")

    # 3. Upload the content of the local file to GitHub



if __name__ == "__main__":
    asyncio.run(main())
