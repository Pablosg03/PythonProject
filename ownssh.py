import socket
import threading
import os

def load_key(file_path):
    """
    Load an RSA key from a file, removing any unnecessary lines.

    Args:
        file_path (str): Path to the key file.
    
    Returns:
        str: The key as a string.
    """
    with open(file_path, "r") as f:
        lines = f.readlines()
        key_lines = [line.strip() for line in lines if "RSA PRIVATE KEY" not in line and 
                     "RSA PUBLIC KEY" not in line and "-----" not in line]
        return "".join(key_lines)
    
def server(public_keys):
    """
    Start the server, authenticate clients, and handle commands.

    Args:
        public_keys (list): List of accepted public keys.
    """
    HOST = "0.0.0.0"
    PORT = 1234

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    print(f"Server started. Listening on {HOST}:{PORT}")

    def handle_client(client_socket, client_address):
        """
        Handle communication with a connected client.

        Args:
            client_socket (socket): The client's socket object.
            client_address (tuple): The client's address (IP, port)
        """
        print(f"Connection established with {client_address}")

        client_public_key = client_socket.recv(1024).decode()
        if client_public_key not in public_keys:
            print("Authentication failed: Public key not recognized")
            client_socket.send("Authentication failed".encode())
            client_socket.close()
            return

        print("Authentication successful")
        client_socket.send("Authentication successful".encode())

        while True:
            try:
                command = client_socket.recv(1024).decode()
                if not command.strip():
                    client_socket.send("Invalid command: Empty input.<<END_OF_OUTPUT>>".encode())
                    continue

                print(f"Command received: {command}")
                output = os.popen(command).read()
                if not output.strip():
                    output = f"Invalid command or no output for: {command}"

                log_file = "server_logs.txt"
                with open(log_file, "a") as log:
                    log.write(f"Client: {client_address}, Command: {command}, Output: {output}\n")

                client_socket.send((output + "----END_OF_OUTPUT----").encode())
            except Exception as e:
                error_message = f"Error executing command: {str(e)}"
                client_socket.send((error_message + "----END_OF_OUTPUT----").encode())

                log_file = "server_logs.txt"
                with open(log_file, "a") as log:
                    log.write(f"Client: {client_address}, Command: {command}, Error: {error_message}\n")

    while True:
        client_socket, client_address = server_socket.accept()
        client_handler = threading.Thread(
            target=handle_client, args=(client_socket, client_address)
        )
        client_handler.start()


def client(ip, private_key_path):
    """
    Connect to the server and send commands.

    Args:
        ip (str): The server's IP address.
        private_key_path (str): Path to the client's private key file.
    """
    HOST = ip
    PORT = 1234

    private_key_clean = load_key(private_key_path)
    public_key_path = "public_key.pem"
    public_key_clean = load_key(public_key_path)

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))

    client_socket.send(public_key_clean.encode())

    response = client_socket.recv(512).decode()
    print(response)

    if "Authentication failed" in response:
        client_socket.close()
        return

    while True:
        command = input("Enter command to execute (or 'exit' to quit): ")
        if command.lower() == "exit":
            break

        client_socket.send(command.encode())

        response = ""
        while True:
            chunk = client_socket.recv(1024).decode()
            if "----END_OF_OUTPUT----" in chunk:
                response += chunk.replace("----END_OF_OUTPUT----", "")
                break
            response += chunk

        if "Invalid command" in response:
            print(response)
        elif not response.strip():
            print("No response from server.")
        else:
            print(response)

    client_socket.close()

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: ownssh.py -s <public_key_1,public_key_2,...> | -c <ip> <private_key>")
        sys.exit(1)

    mode = sys.argv[1]

    if mode == "-s":
        public_keys = []
        if os.path.isfile(sys.argv[2]):
            public_keys = [load_key(sys.argv[2])]
        else:
            public_keys = sys.argv[2].split(",")
        server(public_keys)

    elif mode == "-c":
        if len(sys.argv) != 4:
            print("Usage: ownssh.py -c <ip> <private_key>")
            sys.exit(1)
        ip = sys.argv[2]
        private_key_path = sys.argv[3]
        client(ip, private_key_path)

    else:
        print("Invalid mode. Use -s for server or -c for client.")
