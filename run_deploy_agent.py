"""Start the TRAP deploy agent on the Honeypot machine:
python3 run_deploy_agent.py --config /etc/trap/deploy-agent.json"""
from defender.deploy_agent.agent import main

if __name__ == "__main__":
    raise SystemExit(main())
