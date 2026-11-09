"""Safe local demo: display authorized IDs; does not configure system VPN/firewall."""
import argparse
from .roster import load_roster

def main():
    p = argparse.ArgumentParser(description="WG Access Orchestrator - Stage 1")
    p.add_argument("--roster", default="config/roster.example.json", help="Local demo roster JSON")
    args = p.parse_args()
    roster = load_roster(args.roster)
    print(f"VALIDATED LOCAL ROSTER: {len(roster)} user(s)")
    for uid, group_id in sorted(roster.items()):
        print(f"  user_id={uid}  group_id={group_id}")
    print("No WireGuard peers or nftables rules were modified.")

if __name__ == "__main__":
    main()
