import socket
import threading
import sys
import time
import re
import ast

def open_socket(client_socket,ip):
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)

        message = b'Hello Neighbor'
        start_time = time.time()

        s.settimeout(2)

        s.sendto(message,(ip,24000))
        print(f"Message sent to {ip}:24000")

        try:
            response, _ = s.recvfrom(1024)
            end_time = time.time()

            round_trip_time = end_time - start_time
            round_trip_time_ms = round_trip_time * 1000  # Convert seconds to milliseconds
            print(f"Response from {ip}:24000 -> {response.decode()} (Round-trip time: {round_trip_time_ms:.4f} ms)")
            client_ip = response.decode().split()[1]
            print(f"{client_ip}")
            response_message = f"TIME :{ip},{client_ip},{round_trip_time_ms:.4f},".encode()
            client_socket.sendto(response_message,(HOST,PORT))



        except socket.timeout:
            print(f"No response received from {ip}:24000")
            response_message2 = f"DIED :{ip}".encode()
            client_socket.sendto(response_message2,(HOST,PORT))

        s.close()
    
    except Exception as e:
        print(f"An error occurred with {ip}:24000 -> {e}")

# Função que será usada pelo servidor para ouvir e receber mensagens dos clientes
def handle_client(client_socket):
    while True:
        try:
            # Recebe mensagem do cliente
            message = client_socket.recv(1024).decode()
            if message:
                print(f"Recebido: {message}")
                # Enviar uma resposta para o cliente
                client_socket.send("HELLO from Server".encode())
            else:
                # Encerra a conexão se a mensagem estiver vazia
                print("Conexão fechada.")
                client_socket.close()
                break
        except:
            # Caso ocorra algum erro
            print("Erro na conexão com o cliente.")
            client_socket.close()
            break

# Função para o cliente enviar e receber mensagens do servidor
def client(host, port):
    # Cria o socket do cliente UDP
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # Enviar a mensagem HELLO
    try:
        while True:
            # Enviar a mensagem para o servidor
            message = "HELLO :ID_NODO"
            client_socket.sendto(message.encode(), (host, port))
            print(f"Mensagem enviada para {host} {port}")
            
            # Receber a resposta do servidor
            client_socket.settimeout(1)  # Timeout para evitar bloqueio indefinido
            try:
                response, server_address = client_socket.recvfrom(1024)
                print(f"Resposta do servidor: {response.decode()}")
                ips = re.findall(r'\d+\.\d+\.\d+\.\d+', response.decode())
                print(ips)
                threads = []
                for ip in ips:
                    thread = threading.Thread(target=open_socket,args=(client_socket,ip,))
                    thread.start()
                    threads.append(thread)

                for thread in threads:
                    thread.join()
            except socket.timeout:
                print("Nenhuma resposta recebida do servidor.")

            # Aguarda um tempo antes de enviar a próxima mensagem
            time.sleep(1)  # Tempo de espera entre mensagens (em segundos)

    except KeyboardInterrupt:
        print("\nNodo interrompido pelo usuário.")
    finally:
        client_socket.close()
        print("Socket do cliente fechado.")

# Função do servidor que vai escutar em uma porta específica
def server(host, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((host, port))
    print(f"Servidor ouvindo em {host}:{port}...")

    while True:
        # Escuta por mensagens de qualquer cliente
        message, client_address = server_socket.recvfrom(1024)
        print(f"Recebido de {client_address}: {message.decode()}")
        
        # Verifica se a mensagem recebida é "HELLO"
        if message.decode().strip() == "Hello Neighbor":
            # Envia uma resposta de volta para o cliente
            response = f"HELLO {client_address[0]}"
            server_socket.sendto(response.encode(), client_address)
            print(f"Resposta enviada para {client_address}")

        if message.decode().startswith("REQ:"):
            print("Hello")
            request = message.decode()
            # Remover o prefixo 'REQ:' e dividir o restante da string
            pattern = r"REQ:(?P<host>[^:]+):(?P<port>\d+),(?P<videofile>[^,]+),(?P<response>\[.*\])"

            match = re.match(pattern, request)

            if match:
                host = match.group('host')
                port = match.group('port')
                videofile = match.group('videofile')
                response = match.group('response')

                # Exibir os valores extraídos
                print(f"Host: {host}")
                print(f"Port: {port}")
                print(f"Video file: {videofile}")
                print(f"Response: {response}")

            else:
                print("A string não corresponde ao padrão esperado.")
        else:
            print("Mensagem recebida não é a esperada, aguardando nova mensagem.")


# Definir o host e a porta
HOST = '10.0.17.10'
PORT = 2200

# Iniciar o cliente em uma thread separada
client_thread = threading.Thread(target=client, args=(HOST, PORT))
server_thread = threading.Thread(target=server,args=('0.0.0.0',24000))
server_thread.start()
client_thread.start()

# Esperar que ambas as threads terminem
client_thread.join()
server_thread.join()
