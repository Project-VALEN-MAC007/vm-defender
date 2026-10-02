"""Apply a narrow proxy integration patch to the pinned upstream source."""
from pathlib import Path
import sysconfig

path = Path(sysconfig.get_paths()['purelib']) / 'snare' / 'tanner_handler.py'
source = path.read_text()
needle = '            data["peer"] = peer'
assert source.count(needle) == 1, 'Pinned upstream changed; review proxy patch'
replacement = '''            # Trust a client header only from an explicitly configured proxy.
            import ipaddress
            trusted = os.environ.get("MIMIC_TRUSTED_PROXY_CIDRS", "")
            networks = [ipaddress.ip_network(x.strip()) for x in trusted.split(",") if x.strip()]
            if any(ipaddress.ip_address(peer["ip"]) in net for net in networks):
                original = request.headers.get("X-Real-IP", "")
                try:
                    peer["ip"] = str(ipaddress.ip_address(original))
                except ValueError:
                    pass
            data["peer"] = peer'''
path.write_text(source.replace(needle, replacement))
