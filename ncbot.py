

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

# authenticate the command by comparing macs
def authenticate_cmd(nonce, mac, secret):
    # ignore command if nonce has been seen before
    if nonce in seen_nonces:
        print("This nonce has been seen before")
        return False
    else:
        print('authenticating...')
        seen_nonces.append(nonce)
        # calculate mac
        sha256_hash = hashes.Hash(hashes.SHA256())
        sha256_hash.update((nonce + secret).encode())
        mac2 = sha256_hash.finalize().hex()
        # compare macs
        print(f'compare mac: {mac}, with mac2: {mac2[:8]}')
        if (mac == mac2[:8]):
            print("authentication successfull")
            return True
    return False

# executes the attack command
def execute_attack_cmd(hostname, port, nick, nonce, sock):
    try:
        # connect to the target and send it a message
        print("connecting to target...")
        target_sock = socket.create_connection((hostname,port), timeout=3)
        print("connnected to target server")
        attack_msg = f'{nick} {nonce}\n'
        target_sock.sendall(attack_msg.encode())
        print("attack message sent. Closing connection to attack target...")
        target_sock.close()
        # send OK message to the server
        res_msg = f'-attack {nick} OK'
        sock.sendall(res_msg.encode())
    # handle errors and send the appropriate FAIL message
    except socket.timeout:
        print("Connection timed out")
        res_msg = f'-attack {nick} FAIL timeout'
        sock.sendall(res_msg.encode())
    except ConnectionRefusedError:
        print('connection refused')
        res_msg = f'-attack {nick} FAIL connection refused'
        sock.sendall(res_msg.encode())
    except socket.gaierror as e:
        print(e)
        res_msg = f'-attack {nick} FAIL no such hostname'
        sock.sendall(res_msg.encode())
    except Exception as e:
        print(e)
        res_msg = f'-attack {nick} FAIL' + e
        sock.sendall(res_msg.encode())
    return True

# closes the connection to the current socket
def execute_move_cmd(nick, sock):
    msg = f'-move {nick}\n'
    sock.sendall(msg.encode())
    sock.shutdown(socket.SHUT_WR)
    sock.close()
    return True
    
# executes the given command
def execute_cmd(msg, nick, sock, num_cmds_executed, secret):
    cmd = msg[2]
    match cmd:
        case "status":
            # sends the status of the bot
            msg = f'-status {nick} {num_cmds_executed + 1}\n'
            sock.sendall(msg.encode())
            print("status sent")
            return True, []
        case "shutdown":
            # send shutdown message
            msg = f'-shutdown {nick}\n'
            print("shutting down...")
            sock.sendall(msg.encode())
            # close the socket connection
            sock.shutdown(socket.SHUT_WR)
            sock.close()
            # terminate the program
            sys.exit()
        case "attack":
            # make sure the number of args is correct
            if (len(msg) <= 3):
                print("invalid number of args. <hotname>:<port> expected")
                return False, []
            hostname, port = msg[3].split(':')
            # execture attack command
            return execute_attack_cmd(hostname, port, nick, msg[0], sock), []
        case "move":
            # make sure the number of args is correct
            if (len(msg) <= 3):
                print("invalid number of args. <hotname>:<port> expected")
                return False, [hostname, port]
            hostname, port = msg[3].split(':')
            return execute_move_cmd(nick, sock), [hostname, port]
        # handle any commands not recognized
        case _:
            print("command not recognized")
            return False, []

# start the bot
def start_bot(hostname, port, nick, secret):
    num_cmds_executed = 0
    while(True): 
        try:
            # create the socket connection
            sock = socket.create_connection((hostname,port), timeout=30)
            print("Connected to", hostname, port)
            # send join message
            join_msg = f'-joined {nick}\n'
            sock.sendall(join_msg.encode())
            connected = True
            while (connected):
                # await commands
                msg = sock.recv(1024).decode('ascii').split()
                print(f"received: {msg}")
                # ensure correct number of args and authenticate the message
                if len(msg) >= 3 and authenticate_cmd(msg[0], msg[1], secret):
                    print(f'executing {msg[2]} command...')
                    res, args = execute_cmd(msg, nick, sock, num_cmds_executed, secret)
                    # if the command was executed, increase the counter
                    if res:
                        num_cmds_executed += 1
                        # if there were args returned, that means the move command was executed, so update the hostname and port
                        if len(args) > 0:
                            hostname, port = args
                            print("connecting to", hostname, port)
                            
                elif msg == []:
                    connected = False
                    print('disconnected')
                else:
                    print("message ignored")
        except socket.timeout:
            print("Connection timed out. Attempting to reconnect...")
        except OSError as e:
            if e.errno == 9: # ignore
                pass
            else:
                print(e)
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