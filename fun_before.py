import logging
import argparse
import subprocess
import os
import time
import signal
import json
from datetime import datetime
import sys
import re
import zmq
from vplaned import Controller, ControllerException, DataplaneException

# ---------------- Configuration ----------------

MAX_DURATION = 20 * 60
SERVICE_NAME = "Ue-pkt-capture"
BOX_WIDTH = 72
UE_IP_RETRY_COUNT = 50
UE_IP_RETRY_INTERVAL = 2

CONFIG_PATH = "/etc/vyatta/cfw-load-balancer-epdgdp.json"

# ---------------- Dataplane Helper ----------------

def send_config_to_dataplane(cmds, logger=logging.getLogger(SERVICE_NAME)):
    try:
        with Controller() as controller:
            for dataplane in controller.get_dataplanes():
                with dataplane:
                    for cmd in cmds:
                        logger.debug(f'Running: {cmd}')
                        try:
                            return dataplane.json_command(cmd['cmd'])
                        except Exception:
                            continue
    except Exception:
        return None


# ---------------- EPDGDPLB Helpers ----------------

def load_dp_addresses():
    try:
        with open(CONFIG_PATH) as f:
            text = f.read()

        ips = re.findall(r'"epdgdp"\s*:\s*"([\d.]+)"', text)
        return [f"tcp://{ip}:5555" for ip in ips]

    except Exception:
        return []


def send_to_dp(dp_addr, cmd_str):
    ctx = zmq.Context()
    sock = ctx.socket(zmq.REQ)

    sock.setsockopt(zmq.LINGER, 1000)
    sock.RCVTIMEO = 2000
    sock.connect(dp_addr)

    try:
        sock.send_string(cmd_str)

        try:
            reply = sock.recv_string().strip()
        except zmq.error.Again:
            return None

        if not reply:
            return None

        if reply.startswith('"') and reply.endswith('"'):
            reply = json.loads(reply)

        reply = re.sub(
            r'"lb-info"\s*:\s*\{\s*\[([\s\S]*?)\]\s*\}',
            r'"lb-info": [{\1}]',
            reply
        )


        return json.loads(reply)

    except Exception as e:
        print(f"DEBUG: Failed reply -> {reply}")
        return None

    finally:
        sock.close()
        ctx.term()


def get_epdg_ip_port(ue_identifier):
    dp_addresses = load_dp_addresses()

    if not dp_addresses:
        return None, None

    cmd = f"epdg-op show lb-info ueid {ue_identifier}"

    for dp in dp_addresses:
        resp = send_to_dp(dp, cmd)

        if not resp or "error" in resp:
            continue

        lb_list = resp.get("lb-info")

        if isinstance(lb_list, list) and len(lb_list) > 0:
            lb = lb_list[0]
            ap_ip = lb.get("ap_ip")
            ap_port = lb.get("ap_port")

            if ap_ip and ap_port:
                return ap_ip, ap_port

    return None, None


# ---------------- UE Lookup ----------------

def run_command_to_get_ip_port(ue_identifier: str, nodetype: str):

    nodetype = nodetype.upper()

    if not ue_identifier.isdigit():
        print("==> ERROR: UE identifier must be numeric MSISDN/IMSI")
        sys.exit(1)

    # IMSDP
    if nodetype == "IMSDP":
        cmd = f"imsdp-op show imsdp msisdn ip {ue_identifier}"
        ret = send_config_to_dataplane([{'cmd': cmd, 'oper': True}])

        try:
            ue = ret['imsdp_ue_msisdn_to_ip'][0]
            return ue.get('Local IP'), ue.get('Local Port')
        except Exception:
            return None, None

    # TWAGDP
    elif nodetype == "TWAGDP":
        cmd = f"wigw-op show wigw ue imsi ip {ue_identifier}"
        ret = send_config_to_dataplane([{'cmd': cmd, 'oper': True}])

        try:
            return ret['wigw_ue_ip_from_imsi'].get('ue_ip'), None
        except Exception:
            return None, None

    # EPDGDPLB
    elif nodetype == "EPDGDPLB":
        return get_epdg_ip_port(ue_identifier)

    return None, None


def get_ue_details_with_retry(ue_identifier: str, nodetype: str, logger):

    print("==> INFO: Waiting for UE details....")

    for attempt in range(1, UE_IP_RETRY_COUNT + 1):
        try:
            logger.info(f"Attempt {attempt}/{UE_IP_RETRY_COUNT}")

            ue_ip, ue_port = run_command_to_get_ip_port(ue_identifier, nodetype)

            if nodetype.upper() == "IMSDP" and ue_ip and ue_port:
                return ue_ip, ue_port

            if nodetype.upper() == "TWAGDP" and ue_ip:
                return ue_ip, None

            if nodetype.upper() == "EPDGDPLB" and ue_ip and ue_port:
                return ue_ip, ue_port

            if attempt < UE_IP_RETRY_COUNT:
                time.sleep(UE_IP_RETRY_INTERVAL)

        except KeyboardInterrupt:
            return None, None

    return None, None


# ---------------- BPF ----------------

def ip_to_hex(ip: str):
    return ''.join(f'{int(o):02x}' for o in ip.split('.'))


def build_twagdp_bpf(ue_ip: str):
    ue_hex = ip_to_hex(ue_ip)

    return f"(host {ue_ip} or udp port 2152)"


# ---------------- tcpdump ----------------

def start_tcpdump(interface, ip, port, nodetype, output_file):

    if nodetype in ["IMSDP", "EPDGDPLB"]:
        filt = f"host {ip} and port {port}"
    else:
        filt = build_twagdp_bpf(ip)

    cmd = ["tcpdump", "-i", interface, "-w", output_file, filt]

    return subprocess.Popen(
        cmd,
        preexec_fn=os.setsid,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True
    )


# ---------------- UI ----------------

def box_line_center(text=""):
    return f"║ {text.center(BOX_WIDTH - 4)} ║"


# ---------------- MAIN ----------------

def main():

    parser = argparse.ArgumentParser(description="UE tcpdump capture utility")
    parser.add_argument("nodetype")
    parser.add_argument("ue_identifier")
    parser.add_argument("interface")
    args = parser.parse_args()

    nodetype = args.nodetype.upper()
    ueid = args.ue_identifier
    interface = args.interface

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    outfile = f"{nodetype}_{ueid}_{timestamp}.pcap"

    if not os.path.exists(f"/sys/class/net/{interface}"):
        print(f"Interface {interface} not found")
        return

    logger = logging.getLogger(SERVICE_NAME)

    ue_ip, ue_port = get_ue_details_with_retry(ueid, nodetype, logger)

    # Validation
    if nodetype == "IMSDP" and (not ue_ip or not ue_port):
        print("No UE IP/Port found")
        return

    if nodetype == "TWAGDP" and not ue_ip:
        print("No UE IP found")
        return

    if nodetype == "EPDGDPLB" and (not ue_ip or not ue_port):
        print("No UE session found")
        return

    # UI
    print("╔" + "═" * (BOX_WIDTH - 2) + "╗")
    print(box_line_center(f"!!! UE Packet Capture on {nodetype} !!!"))
    print("╠" + "═" * (BOX_WIDTH - 2) + "╣")

    if nodetype == "IMSDP":
        print(box_line_center(f"UE MSISDN : {ueid}"))

    if nodetype == "EPDGDPLB":
        print(box_line_center(f"UE ID : {ueid}"))

    print(box_line_center(f"UE IP[Port] : {ue_ip}[{ue_port}]"))
    print(box_line_center(f"Interface : {interface}"))
    print(box_line_center(f"File : {outfile}"))
    print("╚" + "═" * (BOX_WIDTH - 2) + "╝")

    print(f"Starting capture on {interface}...")

    process = None
    try:
        process = start_tcpdump(interface, ue_ip, ue_port, nodetype, outfile)
        start = time.time()

        while time.time() - start < MAX_DURATION:
            if process.poll() is not None:
                print("tcpdump failed:", process.stderr.readline())
                return
            time.sleep(1)

    except KeyboardInterrupt:
        print("Stopping capture...")

    finally:
        if process and process.poll() is None:
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGINT)
                process.wait(5)
            except:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)

        print("Capture finished")


if __name__ == "__main__":
    main()
