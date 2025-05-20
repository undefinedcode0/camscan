import asyncio
import ipaddress
import logging
import os
import platform
import time
from typing import List, Tuple, Optional

import discord
from discord import app_commands
from discord.ext import commands

BOT_TOKEN = 'fffuck no'
GUILD_ID: Optional[int] = None  # do sum in here

MAX_CONCURRENCY = 1000
WARN_IP_THRESHOLD = 1000
DEFAULT_PORTS = [22, 80, 443]
logger = logging.getLogger("portscanner")
logger.setLevel(logging.INFO)
fh = logging.FileHandler("portscanner.log")
ch = logging.StreamHandler()
fmt = logging.Formatter("%(asctime)s %(levelname)s: %(message)s")
fh.setFormatter(fmt)
ch.setFormatter(fmt)
logger.addHandler(fh)
logger.addHandler(ch)

intents = discord.Intents.default()
bot = commands.Bot(command_prefix="!", intents=intents)
tree = bot.tree

OWNER_ID = 924466450578690079


def is_admin_or_owner(interaction: discord.Interaction) -> bool:
    # In guild: must have admin perms; in DMs: must be bot owner
    if interaction.guild:
        return interaction.user.guild_permissions.administrator
    return interaction.user.id == OWNER_ID

async def ping_host(ip: str, timeout: float = 1.0) -> bool:
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    elif system == "darwin":
        cmd = ["ping", "-c", "1", "-W", str(int(timeout * 1000)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(int(timeout)), ip]

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    await proc.communicate()
    return proc.returncode == 0


async def scan_port(ip: str, port: int, timeout: float) -> bool:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False


def parse_ip_range(rng: str) -> List[str]:
    if "/" in rng:
        net = ipaddress.ip_network(rng, strict=False)
        return [str(ip) for ip in net.hosts()]
    if "-" in rng:
        start_s, end_s = rng.split("-", 1)
        start = ipaddress.ip_address(start_s.strip())
        end = ipaddress.ip_address(end_s.strip())
        if end < start:
            start, end = end, start
        # summarize_address_range returns networks, unpack hosts from first network
        hosts = []
        for net in ipaddress.summarize_address_range(start, end):
            hosts.extend([str(ip) for ip in net.hosts()])
        return hosts
    return [str(ipaddress.ip_address(rng.strip()))]


def chunk_list(lst: List, n: int):
    for i in range(0, len(lst), n):
        yield lst[i : i + n]


def estimate_time(total_hosts: int, total_ports: int, concurrency: int, timeout: float) -> float:
    return (total_hosts * total_ports * timeout) / concurrency

@tree.command(name="scan", description="Scan an IP range for open TCP ports.")
@app_commands.describe(
    target="CIDR (e.g. 192.168.1.0/24) or hyphen range (e.g. 192.168.1.1-254)",
    ports="Comma-separated ports (default: 22,80,443)",
    timeout="Per-port timeout in seconds (default: 1.0)",
    aggressive="High concurrency up to 1000?",
    pre_ping="Ping hosts before scanning?",
)
@app_commands.allowed_contexts(guilds=True, private_channels=True)
@app_commands.check(is_admin_or_owner)
async def scan(
    interaction: discord.Interaction,
    target: str,
    ports: str = None,
    timeout: float = 1.0,
    aggressive: bool = False,
    pre_ping: bool = True,
):
    await interaction.response.defer(thinking=True)
    try:
        hosts = parse_ip_range(target)
    except Exception:
        return await interaction.followup.send("❌ Invalid IP range format.", ephemeral=True)

    if len(hosts) > WARN_IP_THRESHOLD:
        await interaction.followup.send(f"⚠️ Scanning {len(hosts)} hosts; this may take a while.")

    port_list = DEFAULT_PORTS if not ports else [int(p) for p in ports.split(",") if p.isdigit()]
    concurrency = MAX_CONCURRENCY if aggressive else min(500, len(hosts) * len(port_list), MAX_CONCURRENCY)
    sem = asyncio.Semaphore(concurrency)
    results: List[Tuple[str, int]] = []

    alive_hosts = hosts
    if pre_ping:
        ping_tasks = [ping_host(ip, timeout) for ip in hosts]
        ping_results = await asyncio.gather(*ping_tasks)
        alive_hosts = [ip for ip, up in zip(hosts, ping_results) if up]
        logger.info(f"Pre-ping: {len(alive_hosts)}/{len(hosts)} alive")
        if not alive_hosts:
            return await interaction.followup.send("❌ No hosts responded to ping.")

    est = estimate_time(len(alive_hosts), len(port_list), concurrency, timeout)
    await interaction.followup.send(
        f"🔍 Scanning {len(alive_hosts)} hosts on ports {port_list} with timeout {timeout}s "
        f"and concurrency {concurrency} (est. {est:.1f}s)."
    )

    async def bound_scan(ip: str, port: int):
        async with sem:
            if await scan_port(ip, port, timeout):
                results.append((ip, port))

    scan_tasks = [bound_scan(ip, port) for ip in alive_hosts for port in port_list]
    for batch in chunk_list(scan_tasks, 2000):
        await asyncio.gather(*batch)

    results.sort()
    if not results:
        return await interaction.followup.send("✅ Scan complete. No open ports found.")

    for chunk in chunk_list([f"{ip}:{port}" for ip, port in results], 50):
        await interaction.followup.send("```" + "\n".join(chunk) + "```")

    await interaction.followup.send(f"✅ Scan done. Found {len(results)} open ports.")


@tree.command(name="debug", description="Show bot diagnostics.")
@app_commands.allowed_contexts(guilds=True, private_channels=True)
async def debug(interaction: discord.Interaction):
    info = {
        "Python": platform.python_version(),
        "discord.py": discord.__version__,
        "OS": platform.platform(),
        "Concurrency limit": MAX_CONCURRENCY,
        "Log file": os.path.abspath("portscanner.log"),
        "Uptime (s)": int(time.time() - bot.start_time),
    }
    lines = [f"**{k}**: {v}" for k, v in info.items()]
    await interaction.response.send_message("\n".join(lines))


@tree.command(name="status", description="Bot version and status.")
@app_commands.allowed_contexts(guilds=True, private_channels=True)
async def status(interaction: discord.Interaction):
    await interaction.response.send_message(
        f"PortScannerBot v1.0\nUptime: {int(time.time() - bot.start_time)}s\n"
        f"Guilds: {len(bot.guilds)}"
    )


@scan.error
async def on_scan_error(interaction: discord.Interaction, error):
    msg = getattr(error, "message", str(error))
    logger.error(f"Scan error: {msg}")
    if isinstance(error, app_commands.MissingPermissions):
        return await interaction.response.send_message("❌ You lack permissions.", ephemeral=True)
    await interaction.followup.send(f"❌ Scan failed: {msg}")

@bot.event
async def on_ready():
    bot.start_time = time.time()
    logger.info(f"Logged in as {bot.user} ({bot.user.id})")
    # Fast guild-only sync if GUILD_ID is set, then global sync:
    if GUILD_ID:
        logger.info(f"Syncing to guild {GUILD_ID}...")
        await tree.sync(guild=discord.Object(id=GUILD_ID))
    await tree.sync()  # global registration


if __name__ == "__main__":
    bot.run(BOT_TOKEN)
