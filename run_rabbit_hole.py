"""Start the Rabbit Hole web decoy: python run_rabbit_hole.py --config config/rabbit-hole.json"""
import sys

from defender.rabbit_hole.__main__ import main

if __name__ == "__main__":
    sys.exit(main(["serve"] + sys.argv[1:]))
