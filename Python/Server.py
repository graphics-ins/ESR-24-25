import sys, socket,threading,time,re
import heapq
import networkx as nx
import matplotlib.pyplot as plt

from ServerWorker import ServerWorker

class Server:	

    def __init__(self):
        # Initialize the connection data log as an instance variable
        self.connection_data_log = []
        self.points_presence = ['10.0.8.2,10.0.9.2,10.0.11.2']
        self.graph = nx.DiGraph()
        self.ip_to_node = {}

    
    def main(self):
        threading.Thread(target=self.bootstrapper).start()
        threading.Thread(target=self.rtspSocket).start()  
        server_thread = threading.Thread(target=self.server)
        server_thread.start()



    def server(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_socket.bind(('0.0.0.0', 24000))
        print(f"Servidor ouvindo...")

        while True:
            # Escuta por mensagens de qualquer cliente
            message, client_address = server_socket.recvfrom(1024)
            #print(f"Recebido de {client_address}: {message.decode()}")
            
            # Verifica se a mensagem recebida é "HELLO"
            if message.decode().strip() == "Hello Neighbor":
                # Envia uma resposta de volta para o cliente
                response = f"HELLO {client_address[0]}"
                server_socket.sendto(response.encode(), client_address)
                #print(f"Resposta enviada para {client_address}")
            else:
                print("Mensagem recebida não é a esperada, aguardando nova mensagem.")



    def save_connection_data(self, origin, dest, time):
        # Do not normalize the connection; treat (origin, dest) and (dest, origin) as distinct.
        # Check if an entry with the same origin and dest exists (no sorting).
        for record in self.connection_data_log:
            if record['origin'] == origin and record['dest'] == dest:
                # Update the time if found
                record['time'] = time
                print(f"Updated time for connection from {origin} to {dest} to {time}")
                return

        # If no existing entry is found, create a new record
        origin_node = self.get_node_by_ip(origin)
        dest_node = self.get_node_by_ip(dest)
        
        connection_info = {
            "origin": origin,
            "dest": dest,
            "time": time,
            "origin_node": origin_node,
            "dest_node": dest_node
        }
        
        # Add the new record to the log
        self.connection_data_log.append(connection_info)
        print(f"Added new record for connection from {origin} to {dest} with time: {time}")

        self.add_connection_to_graph(origin_node,dest_node,time)

    def add_connection_to_graph(self, origin_node, dest_node, time):
        if not self.graph.has_node(origin_node):
            self.graph.add_node(origin_node)
            #print(f"Added node: {origin_node}")
    
        if not self.graph.has_node(dest_node):
            self.graph.add_node(dest_node)
            #print(f"Added node: {dest_node}")
        
        # Add the edge with the time as the weight
        self.graph.add_edge(origin_node, dest_node, weight=time)
        #print(f"Edge added: {origin_node} -> {dest_node} with time {time}")

    def build_graph_from_connections(self):
        """Builds the graph using the existing connection data."""
        for record in self.connection_data_log:
            origin_node = record["origin_node"]
            dest_node = record["dest_node"]
            time = record["time"]
            self.add_connection_to_graph(origin_node, dest_node, time)

    def find_shortest_path(self, start_node, end_node):
        """Finds the shortest path between two nodes using Dijkstra's algorithm."""
        try:
            # Dijkstra's algorithm to find the shortest path based on time
            path = nx.dijkstra_path(self.graph, source=start_node, target=end_node, weight='weight')
            total_time = nx.dijkstra_path_length(self.graph, source=start_node, target=end_node, weight='weight')
            
            print(f"Shortest path from {start_node} to {end_node}: {path}")
            print(f"Total time for the path: {total_time}")
            return path, total_time
        except nx.NetworkXNoPath:
            print(f"No path found between {start_node} and {end_node}")
            return None, None

    def visualize_graph(self):
            """Visualizes the graph using matplotlib."""
            
            pos = nx.spring_layout(self.graph)  # Use spring layout for better visualization
            plt.figure(figsize=(10, 8))
            
            # Draw the graph with node labels and edge weights
            nx.draw(self.graph, pos, with_labels=True, node_size=2000, node_color='lightblue', font_size=10, font_weight='bold')
            edge_labels = nx.get_edge_attributes(self.graph, 'weight')
            nx.draw_networkx_edge_labels(self.graph, pos, edge_labels=edge_labels)
            
            plt.title("Network Graph")
            plt.show()

    def rtspSocket(self):
        try:
            SERVER_PORT = int(sys.argv[1])
        except:
            print("[Usage: Server.py Server_port]\n")
            SERVER_PORT = 2000
        rtspSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        rtspSocket.bind(('', SERVER_PORT))
        rtspSocket.listen(5)        

        # Receive client info (address,port) through RTSP/TCP session
        while True:
            clientInfo = {}
            clientInfo['rtspSocket'] = rtspSocket.accept()
            ServerWorker(clientInfo).run()		
                
    def bootstrapper(self):
        """Bootstrapper function to read interfaces and neighbors from config.txt."""
        print("Bootstrapper started, reading configuration file.")
        config_file = 'config.txt'
        try:
            SERVER_PORT2 = int(sys.argv[2])
        except:
            print("[Usage: Server.py Server_port]\n")
            SERVER_PORT2 = 2200

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('', SERVER_PORT2)) 
        print(f"Esperando mensagem")
        groups = self.load_config(config_file)
        self.load_config2(config_file)
        
        # Verifica se o arquivo foi lido corretamente
        if not groups:
            print("Erro: grupos de IP não carregados corretamente. Verifique o arquivo config.txt.")
            return
        
        while True:
            try:
                sock.settimeout(2)
                self.build_graph_from_connections()
                data, addr = sock.recvfrom(1024)
                message = data.decode('utf-8').strip()
                
                # Extrair o IP do cliente
                client_ip = addr[0]

                if message.startswith("Best IP:"):
                    ip_match = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', message)
                    if ip_match:
                        extracted_ip = ip_match.group()
                        print(f"Extracted IP: {extracted_ip}")
                    else:
                        print("No IP found")
                    node = self.get_node_by_ip(extracted_ip)
                    node_host = self.get_node_by_ip('10.0.17.10')
                    start_node = node_host
                    end_node = node
                    if start_node in self.graph.nodes and end_node in self.graph.nodes:
                        path, total_time = self.find_shortest_path(start_node, end_node)
                        print(f"Path: {path} \n Time: {total_time}")
                    else:
                        print(f"One of the nodes ({start_node}, {end_node}) does not exist in the graph.")
                    response_message_client= f"{path}"
                    sock.sendto(response_message_client.encode(),addr)



                if message.startswith("TIME :"):
                    parsed_values = message.replace("TIME :", "").strip(",").split(",")

                    ip = parsed_values[0]
                    client_ip = parsed_values[1]
                    round_trip_time = float(parsed_values[2])

                    
                    self.save_connection_data(ip, client_ip,round_trip_time)

                
                if message == ("CLIENT"):
                    print(f"Mensagem recebida de Cliente {client_ip}")
                    extracted_ips = re.findall(r'\((.*?)\)', self.points_presence[0])
                    print(extracted_ips)
                    for ip in extracted_ips:
                        node_ip = self.get_node_by_ip(ip)
                    response_message = f"Pontos de Presenca: {self.points_presence}"
                    sock.sendto(response_message.encode(), addr)

                if message.startswith ("DIED:"):
                    extracted_ip = message.split("DIED :")[1]
                    print(f"Ip {extracted_ip} died")



                    


                # Verificar se a mensagem é do tipo "HELLO : ID-NODO"
                if message.startswith("HELLO :"):
                    node_id = self.get_node_by_ip(client_ip)
                    print(f"Mensagem recebida do Nodo {node_id}")
                    
                    # Verifica se o IP está no grupo da esquerda
                    for left_ips, right_ips in groups.items():
                        if client_ip in left_ips:
                            # Envia o grupo da direita de volta como resposta
                            response_message = f"Vizinhos: {', '.join(right_ips)}"
                            sock.sendto(response_message.encode(), addr)
                            break  # Envia uma vez e sai do loop, caso o IP tenha sido encontrado
                    else:
                        print(f"IP {client_ip} não está em nenhum nodo")
                        
            except socket.timeout:
                pass
            except Exception as e:
                print(f"Erro ao receber mensagem: {e}")
            


    def load_config(self, config_file):
        """Lê e processa o arquivo de configuração para carregar grupos de IPs."""
        groups = {}
        
        try:
            with open(config_file, 'r') as file:
                for line in file:
                    line = line.strip()
                    
                    # Verifica se a linha começa com "nX :" e remove esse prefixo
                    if re.match(r"n\d+ :", line):
                        # Remove o prefixo "nX :"
                        line = re.sub(r"^n\d+ :", "", line).strip()

                    # Expressão regular para encontrar os grupos de IPs
                    match = re.match(r"\((.*?)\) - \((.*?)\)", line)
                    if match:
                        # Separar os IPs e preencher os grupos
                        left_ips = match.group(1).split(',')
                        right_ips = match.group(2).split(',')
                        
                        left_ips = [ip.strip() for ip in left_ips]
                        right_ips = [ip.strip() for ip in right_ips]
                        
                        # Adiciona a relação de IPs ao dicionário
                        for left_ip in left_ips:
                            groups[left_ip] = right_ips
                    else:
                        print(f"Erro: Formato inválido na linha: {line}")
        except Exception as e:
            print(f"Erro ao ler o arquivo de configuração: {e}")
        
        return groups
    
    def load_config2(self, config_file):
        """Reads the configuration file and maps IP addresses to nodes."""
        try:
            with open(config_file, 'r') as file:
                for line in file:
                    line = line.strip()
                    
                    # Regex pattern to match lines like n1 :(10.0.7.2,...) - (10.0.0.20,...)
                    match = re.match(r"n(\d+) :\s?\((.*?)\)\s?-\s?\((.*?)\)", line)
                    
                    if match:
                        # Extract node number, left IPs and right IPs
                        node_number = match.group(1)  # Node number e.g., '1', '2', etc.
                        left_ips = match.group(2).split(',')
                        right_ips = match.group(3).split(',')
                        
                        # Remove any extra spaces from IP addresses
                        left_ips = [ip.strip() for ip in left_ips]
                        right_ips = [ip.strip() for ip in right_ips]
                        
                        # Map the IPs to the respective node number
                        for ip in left_ips:
                            self.ip_to_node[ip] = node_number
                    else:
                        print(f"Erro: Formato inválido na linha: {line}")
        except Exception as e:
            print(f"Erro ao ler o arquivo de configuração: {e}")

    def get_node_by_ip(self, ip):
        node = self.ip_to_node.get(ip, None)
        if node is None:
            print(f"Warning: IP {ip} not found in ip_to_node mapping")
        return node




    def construir_grafo(self,config_file, connection_info):
        """
        Construi um grafo representando a rede.

        Args:
            config_file (str): Caminho para o arquivo de configuração.
            connection_info (list): Lista de dicionários com informações de conexão.

        Returns:
            nx.Graph: Grafo representando a rede.
        """

        G = nx.Graph()

        with open(config_file, 'r') as f:
            for line in f:
                node, interfaces = line.strip().split('-')
                interfaces = interfaces.split(',')
                for interface in interfaces:
                    G.add_node(interface)

        # Adicionar as arestas com as latências conhecidas
        for connection in connection_info:
            origin, dest, time = connection['origin'], connection['dest'], connection['time']
            G.add_edge(origin, dest, weight=time)

        return G
    
    def find_best_path(self, start, end):
        # Build the graph from the connection data log
        graph = {}
        for record in self.connection_data_log:
            origin = record['origin']
            dest = record['dest']
            time = record['time']
            
            if origin not in graph:
                graph[origin] = []
            if dest not in graph:
                graph[dest] = []
                
            graph[origin].append((dest, time))
            graph[dest].append((origin, time))  # As it's an undirected graph
        
        # Use Dijkstra's algorithm to find the shortest path
        # Priority queue for Dijkstra's
        pq = [(0, start)]  # (distance, node)
        distances = {start: 0}
        previous_nodes = {start: None}
        
        while pq:
            current_distance, current_node = heapq.heappop(pq)
            
            # If we reached the destination, reconstruct the path
            if current_node == end:
                path = []
                while previous_nodes[current_node] is not None:
                    path.append(current_node)
                    current_node = previous_nodes[current_node]
                path.append(start)
                path.reverse()
                return path, distances[end]
            
            # Explore neighbors
            for neighbor, weight in graph.get(current_node, []):
                distance = current_distance + weight
                if neighbor not in distances or distance < distances[neighbor]:
                    distances[neighbor] = distance
                    previous_nodes[neighbor] = current_node
                    heapq.heappush(pq, (distance, neighbor))
        
        # If there's no path from start to end
        return None, float('inf')

if __name__ == "__main__":
    (Server()).main()
    



