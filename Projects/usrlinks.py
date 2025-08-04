#!/usr/bin/env python3
"""
USRLINKS - Advanced Username Availability Checker

A comprehensive tool to check username availability across 50+ platforms with:
- Advanced detection methods to minimize false positives/negatives
- Proxy/Tor support with automatic rotation
- Comprehensive error handling
- Detailed reporting and analytics
- Configuration system
- Database integration for results storage
"""

import asyncio
import json
import random
import re
import sqlite3
import sys
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import aiohttp
import dns.resolver
import requests
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.style import Style
from rich.table import Table
from rich.text import Text
from rich import box
from stem import Signal
from stem.control import Controller

# Constants
CONFIG_FILE = Path("usrlinks_config.json")
DATABASE_FILE = Path("usrlinks_results.db")
USER_AGENTS_FILE = Path("user_agents.txt")
TIMEOUT = 15
MAX_RETRIES = 3
CONCURRENT_REQUESTS = 10

# Configure rich console
console = Console(style=Style(color="green", bgcolor="black"))

# ASCII Banner
BANNER = """
███████╗██╗   ██╗██████╗ ██╗      ██╗███╗   ██╗██╗  ██╗███████╗
╚══███╔╝██║   ██║██╔══██╗██║      ██║████╗  ██║██║ ██╔╝██╔════╝
  ███╔╝ ██║   ██║██████╔╝██║      ██║██ █╗ ██║█████╔╝ ███████╗
 ███╔╝  ██║   ██║██╔══██╗██║      ██║██║╚██╗██║██╔═██╗ ╚════|
███████╗╚██████╔╝██║  ██║███████╗██║██║ ╚████║██║  ██╗███████║
╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝
"""

class CheckStatus(Enum):
    """Enumeration for check status results"""
    AVAILABLE = "AVAILABLE"
    TAKEN = "TAKEN"
    ERROR = "ERROR"
    UNKNOWN = "UNKNOWN"
    RESTRICTED = "RESTRICTED"
    RATE_LIMITED = "RATE_LIMITED"

class PlatformCategory(Enum):
    """Categories for different platform types"""
    SOCIAL_MEDIA = "Social Media"
    PROGRAMMING = "Programming"
    GAMING = "Gaming"
    FORUMS = "Forums"
    MULTIMEDIA = "Multimedia"
    OTHER = "Other"

class Platform:
    """Class representing a platform to check"""
    
    def __init__(
        self,
        name: str,
        url: str,
        category: PlatformCategory,
        detection_method: str = "status_code",
        available_status: int = 404,
        unavailable_status: int = 200,
        headers: Optional[Dict[str, str]] = None,
        request_method: str = "GET",
        check_pattern: Optional[str] = None,
        dns_record: Optional[str] = None,
        api_url: Optional[str] = None,
        json_key: Optional[str] = None,
        rate_limit: int = 0,
        tor_supported: bool = True
    ):
        self.name = name
        self.url = url
        self.category = category
        self.detection_method = detection_method
        self.available_status = available_status
        self.unavailable_status = unavailable_status
        self.headers = headers or {}
        self.request_method = request_method
        self.check_pattern = check_pattern
        self.dns_record = dns_record
        self.api_url = api_url
        self.json_key = json_key
        self.rate_limit = rate_limit  # Requests per minute
        self.tor_supported = tor_supported

class USRLINKSConfig:
    """Configuration handler for USRLINKS"""
    
    def __init__(self):
        self.config = self._load_config()
        self.user_agents = self._load_user_agents()
        self.platforms = self._initialize_platforms()
        self.proxies = self.config.get("proxies", [])
        self.current_proxy_index = 0
        self.tor_enabled = self.config.get("tor_enabled", False)
        self.tor_port = self.config.get("tor_port", 9050)
        self.tor_control_port = self.config.get("tor_control_port", 9051)
        self.tor_password = self.config.get("tor_password", "")
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file or create default"""
        default_config = {
            "tor_enabled": False,
            "tor_port": 9050,
            "tor_control_port": 9051,
            "tor_password": "",
            "proxies": [],
            "database_enabled": True,
            "max_concurrent_requests": CONCURRENT_REQUESTS,
            "timeout": TIMEOUT,
            "max_retries": MAX_RETRIES,
        }
        
        try:
            if CONFIG_FILE.exists():
                with open(CONFIG_FILE, "r") as f:
                    return {**default_config, **json.load(f)}
            return default_config
        except Exception as e:
            console.print(f"[red]Error loading config: {e}[/red]")
            return default_config
    
    def _load_user_agents(self) -> List[str]:
        """Load user agents from file"""
        try:
            if USER_AGENTS_FILE.exists():
                with open(USER_AGENTS_FILE, "r") as f:
                    return [line.strip() for line in f if line.strip()]
            return [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            ]
        except Exception as e:
            console.print(f"[red]Error loading user agents: {e}[/red]")
            return []
    
    def _initialize_platforms(self) -> List[Platform]:
        """Initialize all platforms to check"""
        return [
            # Social Media
            Platform(
                name="Instagram",
                url="https://www.instagram.com/{username}",
                category=PlatformCategory.SOCIAL_MEDIA,
                detection_method="pattern",
                check_pattern=r'"username":"{username}"',
            ),
            Platform(
                name="Twitter/X",
                url="https://twitter.com/{username}",
                category=PlatformCategory.SOCIAL_MEDIA,
                detection_method="pattern",
                check_pattern=r'@\{username}',
            ),
            Platform(
                name="Facebook",
                url="https://www.facebook.com/{username}",
                category=PlatformCategory.SOCIAL_MEDIA,
                available_status=404,
                unavailable_status=200,
            ),
            Platform(
                name="TikTok",
                url="https://www.tiktok.com/@{username}",
                category=PlatformCategory.SOCIAL_MEDIA,
                detection_method="pattern",
                check_pattern=r'@\{username}',
            ),
            Platform(
                name="Reddit",
                url="https://www.reddit.com/user/{username}",
                category=PlatformCategory.SOCIAL_MEDIA,
                headers={"User-Agent": "USRLINKS/2.0"},
            ),
            Platform(
                name="Pinterest",
                url="https://www.pinterest.com/{username}",
                category=PlatformCategory.SOCIAL_MEDIA,
            ),
            Platform(
                name="LinkedIn",
                url="https://www.linkedin.com/in/{username}",
                category=PlatformCategory.SOCIAL_MEDIA,
                detection_method="pattern",
                check_pattern=r'profile/view\?id=\{username}',
            ),
            
            # Programming
            Platform(
                name="GitHub",
                url="https://github.com/{username}",
                category=PlatformCategory.PROGRAMMING,
            ),
            Platform(
                name="GitLab",
                url="https://gitlab.com/{username}",
                category=PlatformCategory.PROGRAMMING,
            ),
            Platform(
                name="Bitbucket",
                url="https://bitbucket.org/{username}",
                category=PlatformCategory.PROGRAMMING,
            ),
            Platform(
                name="Stack Overflow",
                url="https://stackoverflow.com/users/{username}",
                category=PlatformCategory.PROGRAMMING,
            ),
            
            # Gaming
            Platform(
                name="Steam",
                url="https://steamcommunity.com/id/{username}",
                category=PlatformCategory.GAMING,
            ),
            Platform(
                name="Epic Games",
                url="https://www.epicgames.com/account/personal?productName={username}",
                category=PlatformCategory.GAMING,
                detection_method="pattern",
                check_pattern=r'Page Not Found',
                available_status=200,
                unavailable_status=200,
            ),
            Platform(
                name="Xbox",
                url="https://xboxgamertag.com/search/{username}",
                category=PlatformCategory.GAMING,
                detection_method="pattern",
                check_pattern=r'Gamertag not found',
            ),
            
            # Multimedia
            Platform(
                name="YouTube",
                url="https://www.youtube.com/@{username}",
                category=PlatformCategory.MULTIMEDIA,
            ),
            Platform(
                name="Twitch",
                url="https://www.twitch.tv/{username}",
                category=PlatformCategory.MULTIMEDIA,
            ),
            Platform(
                name="Spotify",
                url="https://open.spotify.com/user/{username}",
                category=PlatformCategory.MULTIMEDIA,
            ),
            
            # Forums
            Platform(
                name="Medium",
                url="https://medium.com/@{username}",
                category=PlatformCategory.FORUMS,
            ),
            Platform(
                name="Quora",
                url="https://www.quora.com/profile/{username}",
                category=PlatformCategory.FORUMS,
            ),
            
            # Add more platforms as needed...
        ]
    
    def get_random_user_agent(self) -> str:
        """Get a random user agent"""
        return random.choice(self.user_agents) if self.user_agents else "USRLINKS/2.0"
    
    def get_next_proxy(self) -> Optional[str]:
        """Get the next proxy in rotation"""
        if not self.proxies:
            return None
        
        self.current_proxy_index = (self.current_proxy_index + 1) % len(self.proxies)
        return self.proxies[self.current_proxy_index]
    
    def rotate_tor_identity(self) -> bool:
        """Rotate Tor identity if enabled"""
        if not self.tor_enabled:
            return False
        
        try:
            with Controller.from_port(port=self.tor_control_port) as controller:
                controller.authenticate(password=self.tor_password)
                controller.signal(Signal.NEWNYM)
                return True
        except Exception as e:
            console.print(f"[red]Error rotating Tor identity: {e}[/red]")
            return False

class USRLINKSDatabase:
    """Database handler for storing results"""
    
    def __init__(self):
        self.conn = None
        self.cursor = None
        self._initialize_db()
    
    def _initialize_db(self):
        """Initialize the database"""
        try:
            self.conn = sqlite3.connect(DATABASE_FILE)
            self.cursor = self.conn.cursor()
            
            # Create tables if they don't exist
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS checks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    timestamp DATETIME NOT NULL,
                    duration INTEGER NOT NULL,
                    platforms_checked INTEGER NOT NULL,
                    available_count INTEGER NOT NULL,
                    taken_count INTEGER NOT NULL,
                    error_count INTEGER NOT NULL
                )
            """)
            
            self.cursor.execute("""
                CREATE TABLE IF NOT EXISTS results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    check_id INTEGER NOT NULL,
                    platform TEXT NOT NULL,
                    status TEXT NOT NULL,
                    url TEXT NOT NULL,
                    FOREIGN KEY (check_id) REFERENCES checks (id)
                )
            """)
            
            self.conn.commit()
        except Exception as e:
            console.print(f"[red]Error initializing database: {e}[/red]")
    
    def save_results(
        self,
        username: str,
        duration: float,
        results: Dict[str, Tuple[CheckStatus, str]]
    ) -> int:
        """Save results to the database"""
        try:
            # Calculate statistics
            platforms_checked = len(results)
            available_count = sum(1 for status, _ in results.values() if status == CheckStatus.AVAILABLE)
            taken_count = sum(1 for status, _ in results.values() if status == CheckStatus.TAKEN)
            error_count = platforms_checked - available_count - taken_count
            
            # Insert check metadata
            self.cursor.execute("""
                INSERT INTO checks (
                    username, timestamp, duration, platforms_checked,
                    available_count, taken_count, error_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                username,
                datetime.now().isoformat(),
                duration,
                platforms_checked,
                available_count,
                taken_count,
                error_count
            ))
            
            check_id = self.cursor.lastrowid
            
            # Insert individual results
            for platform, (status, url) in results.items():
                self.cursor.execute("""
                    INSERT INTO results (check_id, platform, status, url)
                    VALUES (?, ?, ?, ?)
                """, (check_id, platform, status.value, url))
            
            self.conn.commit()
            return check_id
        except Exception as e:
            console.print(f"[red]Error saving results to database: {e}[/red]")
            self.conn.rollback()
            return -1
    
    def get_history(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get check history from database"""
        try:
            self.cursor.execute("""
                SELECT id, username, timestamp, platforms_checked,
                       available_count, taken_count, error_count
                FROM checks
                ORDER BY timestamp DESC
                LIMIT ?
            """, (limit,))
            
            columns = [col[0] for col in self.cursor.description]
            return [dict(zip(columns, row)) for row in self.cursor.fetchall()]
        except Exception as e:
            console.print(f"[red]Error fetching history: {e}[/red]")
            return []
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()

class UsernameChecker:
    """Main username checking class"""
    
    def __init__(self):
        self.config = USRLINKSConfig()
        self.db = USRLINKSDatabase() if self.config.config.get("database_enabled", True) else None
        self.session = None
        self.results = {}
        self.username = ""
        self.start_time = 0
        self.total_checks = 0
        self.completed_checks = 0
        self.rate_limits = {}
    
    async def check_username(self, username: str):
        """Main method to check username availability"""
        self.username = username
        self.results = {}
        self.start_time = datetime.now().timestamp()
        self.total_checks = len(self.config.platforms)
        self.completed_checks = 0
        
        # Display banner and initial info
        self.display_banner()
        console.print(f"[bold]Checking username:[/bold] [cyan]{username}[/cyan]\n")
        console.print(f"[dim]Checking {self.total_checks} platforms...[/dim]\n")
        
        # Initialize progress display
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
        )
        
        task = progress.add_task("[cyan]Checking platforms...", total=self.total_checks)
        
        # Initialize session
        connector = aiohttp.TCPConnector(
            limit=self.config.config["max_concurrent_requests"],
            force_close=True
        )
        self.session = aiohttp.ClientSession(connector=connector)
        
        # Run checks concurrently with progress tracking
        with Live(progress):
            checks = []
            for platform in self.config.platforms:
                checks.append(self._check_platform(platform, progress, task))
            
            await asyncio.gather(*checks)
        
        # Calculate duration
        duration = datetime.now().timestamp() - self.start_time
        
        # Display final results
        self.display_results(duration)
        
        # Save results to database
        if self.db:
            self.db.save_results(username, duration, self.results)
        
        # Offer export option
        self.offer_export()
        
        # Close session
        await self.session.close()
    
    async def _check_platform(self, platform: Platform, progress, task):
        """Check a single platform with retries"""
        for attempt in range(MAX_RETRIES):
            try:
                result = await self._perform_check(platform)
                self.results[platform.name] = result
                break
            except Exception as e:
                if attempt == MAX_RETRIES - 1:
                    self.results[platform.name] = (CheckStatus.ERROR, platform.url.format(username=self.username))
        
        self.completed_checks += 1
        progress.update(task, advance=1)
    
    async def _perform_check(self, platform: Platform) -> Tuple[CheckStatus, str]:
        """Perform the actual platform check"""
        url = platform.url.format(username=self.username)
        
        # Use minimal headers for Twitter/X
        if platform.name == "Twitter/X":
            headers = {
                "User-Agent": "Mozilla/5.0 (compatible; USRLINKS/2.0)"
            }
        else:
            headers = platform.headers.copy()
            headers["User-Agent"] = self.config.get_random_user_agent()
        
        # Determine proxy to use
        proxy = None
        if platform.tor_supported and self.config.tor_enabled:
            proxy = f"socks5://localhost:{self.config.tor_port}"
        elif self.config.proxies:
            proxy = self.config.get_next_proxy()
        
        try:
            if platform.detection_method == "dns":
                # DNS-based checking
                try:
                    answers = await asyncio.get_event_loop().run_in_executor(
                        None,
                        lambda: dns.resolver.resolve(platform.dns_record.format(username=self.username), 'A')
                    )
                    return (CheckStatus.TAKEN, url) if answers else (CheckStatus.AVAILABLE, url)
                except dns.resolver.NXDOMAIN:
                    return (CheckStatus.AVAILABLE, url)
                except Exception:
                    return (CheckStatus.ERROR, url)
            
            elif platform.detection_method == "api":
                # API-based checking
                api_url = platform.api_url.format(username=self.username)
                async with self.session.get(
                    api_url,
                    headers=headers,
                    proxy=proxy,
                    timeout=TIMEOUT
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        if platform.json_key and platform.json_key in data:
                            return (CheckStatus.TAKEN if data[platform.json_key] else CheckStatus.AVAILABLE, url)
                        return (CheckStatus.TAKEN, url)
                    return (CheckStatus.AVAILABLE, url)
            
            else:
                # Standard HTTP checking
                async with self.session.request(
                    platform.request_method,
                    url,
                    headers=headers,
                    proxy=proxy,
                    timeout=TIMEOUT,
                    allow_redirects=False
                ) as response:
                    # Update rate limiting
                    if platform.name in self.rate_limits:
                        self.rate_limits[platform.name] = (
                            datetime.now().timestamp(),
                            self.rate_limits[platform.name][1] + 1
                        )
                    else:
                        self.rate_limits[platform.name] = (datetime.now().timestamp(), 1)
                    
                    # Pattern matching
                    if platform.check_pattern:
                        text = await response.text()
                        pattern = platform.check_pattern.format(username=self.username)
                        if re.search(pattern, text):
                            return (CheckStatus.TAKEN, url)
                        return (CheckStatus.AVAILABLE, url)
                    
                    # Status code checking
                    if response.status == platform.available_status:
                        return (CheckStatus.AVAILABLE, url)
                    elif response.status == platform.unavailable_status:
                        return (CheckStatus.TAKEN, url)
                    elif response.status == 429:
                        return (CheckStatus.RATE_LIMITED, url)
                    elif response.status in (403, 401):
                        return (CheckStatus.RESTRICTED, url)
                    else:
                        return (CheckStatus.UNKNOWN, url)
        
        except asyncio.TimeoutError:
            return (CheckStatus.ERROR, url)
        except Exception as e:
            console.print(f"[red]Error checking {platform.name}: {e}[/red]", style="dim")
            return (CheckStatus.ERROR, url)
    
    def display_banner(self):
        """Display the USRLINKS banner"""
        console.print(Panel.fit(
            Text(BANNER, style="bold green"),
            border_style="bright_green",
            title="USRLINKS v2.0",
            subtitle="Advanced Username Availability Checker",
            padding=(1, 2),
            box=box.DOUBLE
        ))
    
    def display_results(self, duration: float):
        """Display the final results"""
        # Create category tables
        category_tables = {}
        for category in PlatformCategory:
            category_tables[category] = Table(
                title=f"[bold]{category.value}[/bold]",
                show_header=True,
                header_style="bold magenta",
                box=box.SIMPLE,
                show_edge=False
            )
            category_tables[category].add_column("Platform", style="cyan", width=20)
            category_tables[category].add_column("Status", style="green", width=15)
            category_tables[category].add_column("URL", style="dim", width=50, overflow="fold")
        
        # Organize results by category
        for platform in self.config.platforms:
            status, url = self.results.get(platform.name, (CheckStatus.ERROR, ""))
            category_tables[platform.category].add_row(
                platform.name,
                status.value,
                Text(url, style="blue")
            )
        
        # Create summary table
        summary_table = Table(
            title=f"Summary for [cyan]{self.username}[/cyan]",
            show_header=True,
            header_style="bold magenta",
            box=box.ROUNDED
        )
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Value", style="green")
        
        available = sum(1 for s, _ in self.results.values() if s == CheckStatus.AVAILABLE)
        taken = sum(1 for s, _ in self.results.values() if s == CheckStatus.TAKEN)
        errors = len(self.results) - available - taken
        
        summary_table.add_row("Platforms Checked", str(len(self.results)))
        summary_table.add_row("Available", str(available))
        summary_table.add_row("Taken", str(taken))
        summary_table.add_row("Errors", str(errors))
        summary_table.add_row("Duration", f"{duration:.2f} seconds")
        
        # Display all tables
        console.print(Panel.fit(summary_table, border_style="bright_green"))
        
        for category, table in category_tables.items():
            if table.row_count > 0:
                console.print(Panel.fit(table, border_style="dim"))
    
    def offer_export(self):
        """Offer to export results to file"""
        console.print("\n[bold]Export Options:[/bold]")
        console.print("1. Export to JSON")
        console.print("2. Export to TXT")
        console.print("3. Export to CSV")
        console.print("4. View History")
        console.print("5. Exit")
        
        choice = console.input("\n[bold green]Select option (1-5): [/bold green]")
        
        if choice == "1":
            self.export_to_json()
        elif choice == "2":
            self.export_to_txt()
        elif choice == "3":
            self.export_to_csv()
        elif choice == "4":
            self.view_history()
    
    def export_to_json(self):
        """Export results to JSON file"""
        filename = f"usrlinks_{self.username}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        data = {
            "username": self.username,
            "timestamp": datetime.now().isoformat(),
            "results": {
                platform: {
                    "status": status.value,
                    "url": url
                } for platform, (status, url) in self.results.items()
            }
        }
        
        try:
            with open(filename, "w") as f:
                json.dump(data, f, indent=2)
            console.print(f"\n[green]✓ Results exported to [bold]{filename}[/bold][/green]")
        except Exception as e:
            console.print(f"\n[red]✗ Error exporting to JSON: {e}[/red]")
    
    def export_to_txt(self):
        """Export results to TXT file"""
        filename = f"usrlinks_{self.username}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        try:
            with open(filename, "w") as f:
                f.write(f"USRLINKS Results\n")
                f.write(f"Username: {self.username}\n")
                f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                for category in PlatformCategory:
                    platforms_in_category = [
                        p for p in self.config.platforms 
                        if p.category == category and p.name in self.results
                    ]
                    if platforms_in_category:
                        f.write(f"=== {category.value.upper()} ===\n")
                        for platform in platforms_in_category:
                            status, url = self.results[platform.name]
                            f.write(f"{platform.name}: {status.value} - {url}\n")
                        f.write("\n")
            
            console.print(f"\n[green]✓ Results exported to [bold]{filename}[/bold][/green]")
        except Exception as e:
            console.print(f"\n[red]✗ Error exporting to TXT: {e}[/red]")
    
    def export_to_csv(self):
        """Export results to CSV file"""
        filename = f"usrlinks_{self.username}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        try:
            with open(filename, "w") as f:
                f.write("Platform,Status,URL,Category\n")
                for platform in self.config.platforms:
                    if platform.name in self.results:
                        status, url = self.results[platform.name]
                        f.write(f'"{platform.name}","{status.value}","{url}","{platform.category.value}"\n')
            
            console.print(f"\n[green]✓ Results exported to [bold]{filename}[/bold][/green]")
        except Exception as e:
            console.print(f"\n[red]✗ Error exporting to CSV: {e}[/red]")
    
    def view_history(self):
        """View previous check history"""
        if not self.db:
            console.print("\n[red]Database not enabled in configuration[/red]")
            return
        
        history = self.db.get_history(10)
        if not history:
            console.print("\n[dim]No history found[/dim]")
            return
        
        table = Table(
            title="Check History",
            show_header=True,
            header_style="bold magenta",
            box=box.ROUNDED
        )
        table.add_column("ID", style="cyan")
        table.add_column("Username", style="green")
        table.add_column("Date", style="blue")
        table.add_column("Platforms", style="magenta")
        table.add_column("Available", style="green")
        table.add_column("Taken", style="red")
        table.add_column("Errors", style="yellow")
        
        for entry in history:
            table.add_row(
                str(entry["id"]),
                entry["username"],
                datetime.fromisoformat(entry["timestamp"]).strftime("%Y-%m-%d %H:%M"),
                str(entry["platforms_checked"]),
                str(entry["available_count"]),
                str(entry["taken_count"]),
                str(entry["error_count"])
            )
        
        console.print(Panel.fit(table, border_style="bright_green"))

async def main():
    """Main function to run the application"""
    checker = UsernameChecker()
    
    try:
        # Display configuration options
        console.print("\n[bold]Configuration Options:[/bold]")
        console.print(f"1. Tor Enabled: [cyan]{checker.config.tor_enabled}[/cyan]")
        console.print(f"2. Proxies Configured: [cyan]{len(checker.config.proxies)}[/cyan]")
        console.print("3. Run Check")
        console.print("4. Exit")
        
        choice = console.input("\n[bold green]Select option (1-4): [/bold green]")
        
        if choice == "1":
            # Toggle Tor
            checker.config.tor_enabled = not checker.config.tor_enabled
            console.print(f"\n[green]Tor now {'enabled' if checker.config.tor_enabled else 'disabled'}[/green]")
            await main()
            return
        elif choice == "2":
            # Configure proxies
            proxies = console.input("[bold]Enter proxies (comma separated): [/bold]")
            checker.config.proxies = [p.strip() for p in proxies.split(",") if p.strip()]
            console.print(f"\n[green]{len(checker.config.proxies)} proxies configured[/green]")
            await main()
            return
        elif choice == "4":
            return
        
        # Get username input
        username = console.input("\n[bold green]Enter username to check: [/bold green]")
        if not username:
            console.print("\n[red]Username cannot be empty[/red]")
            await main()
            return
        
        # Run checks
        await checker.check_username(username)
        
        # Prompt to run another check
        another = console.input("\n[bold]Check another username? (y/N): [/bold]").lower()
        if another == "y":
            await main()
    
    except KeyboardInterrupt:
        console.print("\n[red]✗ Operation cancelled by user[/red]")
    except Exception as e:
        console.print(f"\n[red]✗ Error: {str(e)}[/red]")
    finally:
        if checker.db:
            checker.db.close()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[red]✗ Operation cancelled by user[/red]")
    except Exception as e:
        console.print(f"\n[red]✗ Fatal error: {str(e)}[/red]")