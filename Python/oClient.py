import socket
import threading
import sys
import time
import re
import ast

SERVER_HOST = '10.0.17.10'
SERVER_PORT = 2200

class Client:
    best_time = float('Inf')
    best_ip = None
    best_time_lock = threading.Lock()

    @staticmethod
    def open_socket_client(ip):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            message = b'Hello Neighbor'
            start_time = time.time()

            s.settimeout(1)

            s.sendto(message, (ip, 24000))
            print(f"Message sent to {ip}:24000")

            try:
                response, _ = s.recvfrom(1024)
                end_time = time.time()

                round_trip_time = end_time - start_time
                round_trip_time_ms = round_trip_time * 1000  # Convert seconds to milliseconds
                print(f"Response from {ip}:24000 -> {response.decode()} (Round-trip time: {round_trip_time_ms:.4f} ms)")
                client_ip = response.decode().split()[1]
                print(f"{client_ip}")
                with Client.best_time_lock:
                    if round(round_trip_time_ms,4) < round(Client.best_time,4):
                        Client.best_time = round_trip_time_ms
                        Client.best_ip = ip

            except socket.timeout:
                print(f"No response received from {ip}:24000")

            s.close()
        
        except Exception as e:
            print(f"An error occurred with {ip}:24000 -> {e}")

    @staticmethod
    def client_node():
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_socket.bind(('0.0.0.0', 24000))
        print(f"Servidor ouvindo...")

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
            
            if message.decode().startswith("STREAM:"):
                print("Hello there")
            else:
                print("Mensagem recebida não é a esperada, aguardando nova mensagem.")

    @staticmethod
    def client(host, port):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        videofile = sys.argv[1]
        # Enviar a mensagem HELLO
        try:
            
            # Enviar a mensagem para o servidor
            message = "CLIENT"
            client_socket.sendto(message.encode(), (host, port))
            print("Mensagem enviada.")

            # Receber a resposta do servidor
            client_socket.settimeout(1)  # Timeout para evitar bloqueio indefinido
            try:
                response, server_address = client_socket.recvfrom(1024)
                #print(f"Resposta do servidor: {response.decode()}")
                ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', response.decode())
                print(ips)
                threads = []
                for ip in ips:
                    thread = threading.Thread(target=Client.open_socket_client,args=(ip,))
                    thread.start()
                    threads.append(thread)
                    
                for thread in threads:
                    thread.join()
                    
                if Client.best_ip is not None:
                    request = f"REQ:{host}:{port},{videofile}"
                    s1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s1.sendto(request.encode(), (Client.best_ip, 24000))



                    


            except socket.timeout:
                print("Nenhuma resposta recebida do servidor.")

            # Aguarda um tempo antes de enviar a próxima mensagem
            time.sleep(1)  # Tempo de espera entre mensagens (em segundos)

        except KeyboardInterrupt:
            print("\nCliente interrompido pelo usuário.")
        finally:
            client_socket.close()
            print("Socket do cliente fechado.")

# Starting the server and client threads
server_thread = threading.Thread(target=Client.client_node)
server_thread.start()

client_thread = threading.Thread(target=Client.client, args=(SERVER_HOST, SERVER_PORT))
client_thread.start()

client_thread.join()  # Wait for the client thread to finish
