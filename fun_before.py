import logging
import argparse
import subprocess
import os
import time
import signal
import json
from datetime import datetime
import sys
import zmq
from vplaned import Controller, ControllerException, DataplaneException

# ---------------- Configuration ----------------

MAX_DURATION = 20 * 60
SERVICE_NAME = "Ue-pkt-capture"
BOX_WIDTH = 72
UE_IP_RETRY_COUNT = 50
UE_IP_RETRY_INTERVAL = 2  # seconds

# ---------------- Dataplane Helper ----------------

def send_config_to_dataplane(cmds, logger=logging.getLogger(SERVICE_NAME)):
    try:
        with Controller() as controller:
            for dataplane in controller.get_dataplanes():
                with dataplane:
                    for cmd in cmds:
                        logger.debug(f'Running: {cmd}')
                        if 'cmd_name' in cmd:
                            dataplane._socket.send_string('protobuf', flags=zmq.SNDMORE)
                            dataplane._socket.send(cmd['cmd'])
                            return dataplane._socket.recv_string()
                        else:
                            return dataplane.json_command(cmd['cmd'])
    except (ControllerException, DataplaneException, Exception):
        logger.exception("Dataplane command failed")
        print("==> ERROR: Unable to get Response from DP.")
        sys.exit(1)

# ---------------- UE IP & Port Lookup ----------------

def run_command_to_get_ip_port(ue_identifier: str, nodetype: str):
    """
    Queries the dataplane and parses the JSON for 'UE IP' and 'UE Port'.
    Returns a tuple (ip, port) (for IMSDP), or (ip, None) (for TWAGDP) or (None, None).
    """

    nodetype = nodetype.upper()

    if not ue_identifier.isdigit():
        print("==> ERROR: UE identifier must be numeric MSISDN/IMSI")
        sys.exit(1)

    # -------- IMSDP --------
    if nodetype == "IMSDP":
        command = f"imsdp-op show imsdp msisdn ip {ue_identifier}"
        final_cmd = [{'cmd': command, 'oper': True}]
        ret = send_config_to_dataplane(final_cmd)

        if isinstance(ret, dict):
            try:
                ue_data = ret['imsdp_ue_msisdn_to_ip'][0]
                ue_ip = ue_data.get('Local IP')
                ue_port = ue_data.get('Local Port')
                return ue_ip, ue_port
            except (KeyError, IndexError):
                return None, None
    
    # -------- TWAGDP --------
    elif nodetype == "TWAGDP":
        command = f"wigw-op show wigw ue imsi ip {ue_identifier}"
        final_cmd = [{'cmd': command, 'oper': True}]
        ret = send_config_to_dataplane(final_cmd)

        if isinstance(ret, dict):
            try:
                ue_data = ret['wigw_ue_ip_from_imsi']
                ue_ip = ue_data.get('ue_ip')
                return ue_ip, None
            except (KeyError, IndexError):
                return None, None

    # --------- EPDGDPLB ------
    elif nodetype == "EPDGDPLB":
        command = f"epdg-op show lb-info ue-id {ue_identifier}"
        final_cmd = [{'cmd': command, 'oper': True}]
        ret = send_config_to_dataplane(final_cmd)

        if isinstance(ret, dict):
            try:
                ue_data = ret['wigw_ue_ip_from_imsi']
                ue_ip = ue_data.get('ap_ip')
                ue_port= ue_data.get('ap_port')
                return ue_ip, ue_port
            except (KeyError, IndexError):
                return None, None



    else:
        print("==> ERROR: Unsupported nodetype. Supported for IMSDP & TWAGDP.")
        sys.exit(1)

    return None, None

def get_ue_details_with_retry(ue_identifier: str, nodetype: str, logger):
    print("==> INFO: Waiting for UE details....")
    nodetype = nodetype.upper()

    for attempt in range(1, UE_IP_RETRY_COUNT + 1):
        try:
            logger.info(f"Attempt {attempt}/{UE_IP_RETRY_COUNT}")
            ue_ip, ue_port = run_command_to_get_ip_port(ue_identifier, nodetype)

            if nodetype == "IMSDP" and ue_ip and ue_port:
                return ue_ip, ue_port
            
            if nodetype == "TWAGDP" and ue_ip:
                return ue_ip, None

            if attempt < UE_IP_RETRY_COUNT:
                time.sleep(UE_IP_RETRY_INTERVAL)

        except KeyboardInterrupt:
            print("==> INFO: UE lookup interrupted by user")
            return None, None
        except Exception as e:
            logger.debug(f"UE lookup attempt failed: {e}")

    return None, None

# ---------------- IP to Hex ----------------
def ip_to_hex(ip: str):
    return ''.join(f'{int(octet):02x}' for octet in ip.split('.'))

# ---------------- Build BPF filter for TWAGDP ----------------
def build_twagdp_bpf(ue_ip: str):
    ue_hex = ip_to_hex(ue_ip)

    return f"""
(
  (host {ue_ip})
  or
  (ip proto gre and
    ip[22:2] = 0x0800 and
    (ip[36:4] = 0x{ue_hex} or ip[40:4] = 0x{ue_hex}))
  or
  (ip proto gre and
    ip[22:2] = 0x6558 and
    (ip[50:4] = 0x{ue_hex} or
     ip[54:4] = 0x{ue_hex} or
     ip[58:4] = 0x{ue_hex}))
  or
  (udp port 2152 and
    (
      udp[28:4] = 0x{ue_hex} or
      udp[32:4] = 0x{ue_hex} or
      udp[36:4] = 0x{ue_hex}))
)
""".strip()


# ---------------- tcpdump ----------------

def start_tcpdump(interface: str, ue_ip: str, ue_port: str, nodetype: str, output_file: str) -> subprocess.Popen:
    """
    Starts tcpdump with a filter.
    IMSDP -> host IP and port.
    TWAGDP -> host IP.
    """

    nodetype = nodetype.upper()

    if nodetype == "IMSDP":
        # Filter: host <IP> and port <PORT>
        tcpdump_filter = f"host {ue_ip} and port {ue_port}"
    elif nodetype == "TWAGDP":
        tcpdump_filter = build_twagdp_bpf(ue_ip)
    else:
        raise ValueError("Unsupported nodetype")
    
    command = [
        "tcpdump",
        "-i", interface,
        "-w", output_file,
        tcpdump_filter
    ]
    
    return subprocess.Popen(
        command,
        preexec_fn=os.setsid,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

# ---------------- UI Helpers ----------------

def box_line_center(text=""):
    return f"║ {text.center(BOX_WIDTH - 4)} ║"

# ---------------- Main ----------------

def main():
    parser = argparse.ArgumentParser(description="UE tcpdump capture utility")
    parser.add_argument("nodetype")
    parser.add_argument("ue_identifier")
    parser.add_argument("interface")
    args = parser.parse_args()

    nodetype = args.nodetype
    ue_identifier = args.ue_identifier
    interface = args.interface

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_filename = f"{nodetype.upper()}_{ue_identifier}_{timestamp}.pcap"

    # ---- Interface check ----
    if not os.path.exists(f"/sys/class/net/{interface}"):
        print(f"==> ERROR: Interface '{interface}' does not exist")
        return

    logger = logging.getLogger(SERVICE_NAME)

    # Fetch IP and Port
    ue_ip, ue_port = get_ue_details_with_retry(ue_identifier, nodetype, logger)

    if nodetype.upper() == "IMSDP":
        if not ue_ip or not ue_port:
            print("==> INFO: UE IP/Port not found. Exiting")
            return
    elif nodetype.upper() == "TWAGDP":
        if not ue_ip:
            print("==> INFO: UE IP not found. Exiting")
            return
    else:
        print("==> INFO: UE Packet Capture is supported for IMSDP & TWAGDP!")
        return

    print("╔" + "═" * (BOX_WIDTH - 2) + "╗")
    print(box_line_center(f"!!! UE Packet Capture on {nodetype.upper()} !!!"))
    print("╠" + "═" * (BOX_WIDTH - 2) + "╣")

    if nodetype.upper() == "IMSDP":
        print(box_line_center(f"UE Msisdn : {ue_identifier}"))
        print(box_line_center(f"UE IP[Port] : {ue_ip}[{ue_port}]"))
    
    if nodetype.upper() == "TWAGDP":
        print(box_line_center(f"UE IP : {ue_ip}"))

    print(box_line_center(f"Interface : {interface}"))
    print(box_line_center(f"Max Duration : {MAX_DURATION // 60} min or Ctrl+C"))
    print(box_line_center(f"File Name : {output_filename}"))
    print("╚" + "═" * (BOX_WIDTH - 2) + "╝")

    if nodetype.upper() == "IMSDP":
        print(f"==> INFO: Starting tcpdump on {interface} for {ue_ip}:{ue_port}")
    else:
        print(f"==> INFO: Starting tcpdump on {interface} for {ue_ip}")


    process = None
    try:
        process = start_tcpdump(interface, ue_ip, ue_port, nodetype, output_filename)
        start_time = time.time()

        while time.time() - start_time < MAX_DURATION:
            if process.poll() is not None:
                stderr = process.stderr.read().strip()
                print(f"==> ERROR: tcpdump failed: {stderr}")
                return
            time.sleep(1)

        print("==> INFO: Max duration reached. Stopping tcpdump")

    except KeyboardInterrupt:
        print("==> INFO: Ctrl+C detected. Stopping tcpdump")

    finally:
        if process and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGINT)
                process.wait(timeout=5)
            except Exception:
                os.killpg(process.pid, signal.SIGKILL)

        print("==> INFO: Capture finished.")

# ---------------- Entry ----------------

if __name__ == "__main__":
    main()
