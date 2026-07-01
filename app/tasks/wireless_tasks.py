from app.extensions import celery_app, db
from app.models.wireless import WirelessScan, WirelessNetwork, WirelessCapture
from app.plugins.wifite2_adapter import Wifite2Adapter
from app.plugins.hcxdumptool_adapter import HcxdumptoolAdapter
from app.plugins.hcxtools_adapter import HcxtoolsAdapter
import subprocess
import os
from datetime import datetime

PCAP_DIR = os.path.join(os.getcwd(), 'captures')
HASH_DIR = os.path.join(os.getcwd(), 'hashes')
os.makedirs(PCAP_DIR, exist_ok=True)
os.makedirs(HASH_DIR, exist_ok=True)

@celery_app.task(name='wireless_tasks.run_wifite2_scan')
def run_wifite2_scan(interface: str = 'wlan0', scan_id: int = None):
    from app import create_app
    app = create_app()
    with app.app_context():
        scan = WirelessScan.query.get(scan_id)
        if not scan:
            return "Scan not found"

        scan.status = 'running'
        db.session.commit()

        try:
            cmd = ['sudo', 'wifite', '--interface', interface, '--scan', '--kill', '--skip-crack']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            raw = result.stdout + result.stderr

            adapter = Wifite2Adapter()
            networks = adapter.normalize(raw, scan_id=scan_id)

            for n in networks:
                net = WirelessNetwork(
                    scan_id=scan_id,
                    bssid=n['bssid'],
                    essid=n['essid'],
                    channel=n['channel'],
                    encryption=n['encryption']
                )
                db.session.add(net)
                db.session.flush()

                net_raw = next((x for x in networks if x['bssid'] == n['bssid']), None)
                if net_raw:
                    net.signal = net_raw.get('signal')
                    net.is_wps = net_raw.get('is_wps', False)

            scan.status = 'done'
            scan.completed_at = datetime.utcnow()
            db.session.commit()
            return f"Wifite2 scan complete: {len(networks)} networks found"

        except subprocess.TimeoutExpired:
            scan.status = 'failed'
            scan.error_log = 'Wifite2 timed out after 120s'
            db.session.commit()
            return "Timeout"
        except Exception as e:
            scan.status = 'failed'
            scan.error_log = str(e)
            db.session.commit()
            return f"Error: {e}"

@celery_app.task(name='wireless_tasks.run_hcxdumptool_capture')
def run_hcxdumptool_capture(interface: str, bssid: str, channel: int, scan_id: int = None, network_id: int = None):
    from app import create_app
    app = create_app()
    with app.app_context():
        pcap_path = os.path.join(PCAP_DIR, f'capture_{network_id}_{bssid.replace(":","")}_{datetime.utcnow().strftime("%Y%m%d%H%M%S")}.pcapng')

        capture = WirelessCapture(
            scan_id=scan_id,
            network_id=network_id,
            capture_type='pmkid',
            status='capturing',
            pcap_path=pcap_path
        )
        db.session.add(capture)
        db.session.commit()
        cap_id = capture.id

        try:
            cmd = ['sudo', 'hcxdumptool', '-i', interface, '-o', pcap_path,
                   '-t', bssid, '-c', str(channel), '--enable_status']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            raw = result.stdout + result.stderr

            adapter = HcxdumptoolAdapter()
            captures = adapter.normalize(raw, scan_id=scan_id, network_id=network_id)

            if captures:
                cap_info = captures[0]
                capture.capture_type = cap_info.get('capture_type', 'unknown')
                capture.raw_output = raw
                capture.status = 'done'
            else:
                capture.status = 'failed'
                capture.raw_output = raw

            db.session.commit()
            return f"Capture {cap_id}: {capture.status}"

        except subprocess.TimeoutExpired:
            capture.status = 'failed'
            capture.raw_output = 'hcxdumptool timed out'
            db.session.commit()
            return "Timeout"
        except Exception as e:
            capture.status = 'failed'
            capture.raw_output = str(e)
            db.session.commit()
            return f"Error: {e}"

@celery_app.task(name='wireless_tasks.run_hcxtools_convert')
def run_hcxtools_convert(capture_id: int):
    from app import create_app
    app = create_app()
    with app.app_context():
        capture = WirelessCapture.query.get(capture_id)
        if not capture or not capture.pcap_path:
            return "Capture or pcap not found"

        pcap = capture.pcap_path
        base = os.path.splitext(os.path.basename(pcap))[0]
        hash_path = os.path.join(HASH_DIR, f'{base}_hash.txt')
        potfile_path = os.path.join(HASH_DIR, f'{base}_potfile.txt')

        try:
            if capture.capture_type == 'pmkid':
                cmd = ['hcxpcapngtool', '-o', hash_path, '-n', potfile_path, pcap]
            else:
                cmd = ['hcxpcapngtool', '-o', hash_path, '-E', potfile_path, pcap]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            raw = result.stdout + result.stderr

            if os.path.exists(hash_path):
                with open(hash_path) as f:
                    hash_content = f.read()

                adapter = HcxtoolsAdapter()
                if adapter.validate_input(hash_content):
                    capture.hash_file_path = hash_path
                    capture.hash_format = '22000'
                    capture.status = 'converted'
                else:
                    capture.status = 'convert_failed'
                    capture.raw_output = raw
            else:
                capture.status = 'convert_failed'
                capture.raw_output = raw

            db.session.commit()
            return f"Converted: {hash_path}"

        except Exception as e:
            capture.status = 'convert_failed'
            capture.raw_output = str(e)
            db.session.commit()
            return f"Error: {e}"
