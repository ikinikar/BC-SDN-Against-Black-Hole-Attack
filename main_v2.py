

#!/usr/bin/python

import sys
import getopt
import json
import random
import math
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
from collections import deque
import random
import sys
import numpy as np
from collections import OrderedDict

# Code from https://www.udacity.com/blog/2021/10/implementing-dijkstras-algorithm-in-python.html to  create a graph class
class Graph(object):
    def __init__(self, nodes, init_graph):
        self.nodes = nodes
        self.graph = self.construct_graph(nodes, init_graph)
        
    def construct_graph(self, nodes, init_graph):
        '''
        This method makes sure that the graph is symmetrical. In other words, if there's a path from node A to B with a value V, there needs to be a path from node B to node A with a value V.
        '''
        graph = {}
        for node in nodes:
            graph[node] = {}
        
        graph.update(init_graph)
        
        for node, edges in graph.items():
            for adjacent_node, value in edges.items():
                if graph[adjacent_node].get(node, False) == False:
                    graph[adjacent_node][node] = value
                    
        return graph
    
    def get_nodes(self):
        "Returns the nodes of the graph."
        return self.nodes
    
    def get_outgoing_edges(self, node):
        "Returns the neighbors of a node."
        connections = []
        for out_node in self.nodes:
            if self.graph[node].get(out_node, False) != False:
                connections.append(out_node)
        return connections
    
    def value(self, node1, node2):
        "Returns the value of an edge between two nodes."
        return self.graph[node1][node2]
      
    # My addition out of necessity
    def adjustWeights(self, path):
        for p in range(1, len(path)-1): # Need to exclude start/end nodes
            arr = self.get_outgoing_edges(path[p])
            for a in arr:
                self.graph[a][path[p]] = sys.maxsize


def main(num_malicious):
    #outputFile = '/Users/ishankinikar/Desktop/Simulator/output_one'

    real_nodes = 100
    channels = 1

    maxXCoord= 10
    maxYCoord = 10

    minLinks = 10
    maxLinks = 20

    channelRates = [100]

    topologies = 1


    r_startindex = 1
    r_endindex = real_nodes

    fn = 1
    while fn < topologies + 1:
        topology = {"nodes": [], "channels": [], "connections": []}

        # Add channels.
        for ch in range(1, channels + 1):
            topology["channels"].append({
                "channel_id": "channel" + str(ch),
                "data_rate": str(channelRates[random.randint(
                    0, len(channelRates) - 1)])})
        
       
        nodes = {}
        connections = []
        nodesDict = {}
        nodeConnections = []
        for r in range(r_startindex, r_endindex + 1):
            xCoord = round(random.uniform(0, maxXCoord), 
                           2)
            yCoord = round(random.uniform(0, maxYCoord), 
                           2)
            topology["nodes"].append({
                "node_id": "node" + str(r),
                "node_type": "router",
                "x-coord": str(xCoord), 
                "y-coord": str(yCoord)
                })
            nodesDict[r] = [xCoord, yCoord]
            nodes[r] = [xCoord, yCoord]

        

        # Connect each node to nearest N neighboring nodes.
        for r in range(r_startindex, r_endindex + 1):
            nearest = nearestN(nodesDict, r, 
                               nodesDict[r][0],
                               nodesDict[r][1],
                               random.randint(minLinks,
                                              maxLinks))
            for i in range(0, len(nearest)):
                tmp = str(r) + "-" + str(nearest[i][0])
                if tmp not in nodeConnections:
                    weight = round(random.uniform(0.0, 100.0), 4)
                    topology["connections"].append({
                        "source_id": "node" + str(r),
                        "destination_id": "node" + str(nearest[i][0]),
                        "weight": weight
                        })
                    nodeConnections.append(tmp)
                    connections.append([r, nearest[i][0], weight])

       
        # Verify that the graph has a single component.
        if not isConnected(nodes, connections):
            continue

        # Write out json file.
##        with open(outputFile + "_" + str(fn) + ".json", "w") as ofile:
##            json.dump(topology, ofile, sort_keys=True,
##                      indent=4, separators=(',', ': '))

        fn = fn + 1

    # Conversion of format to graph object
    nodes_list = []
    for x in range(1, real_nodes+1):
        nodes_list.append(x)
    init_graph = {}
    for node in nodes_list:
        init_graph[node] = {}
        for c in connections:
            if c[0] == node:
                init_graph[node][c[1]] = c[2]


    graph = Graph(nodes_list, init_graph)

    # Choose Malicious Nodes And Start/End Nodes
    mal = random.sample(range(1, 100), num_malicious)
    start = random.sample(list(set(range(1,100)) - set(mal)), 1)
    end = random.sample(list(set(range(1,100)) - set(mal) - set(start) - set(graph.get_outgoing_edges(start[0]))), 1) # Topologies where start --> end is a connection is impractical
    


    # ----------Normal Dijkstra Simulation--------------
    # Working the Dijkstra Algorithm to find shortest path to send through
    previous_nodes, shortest_path = dijkstra_algorithm(graph = graph, start_node = start[0])
    path, dist = return_result(previous_nodes, shortest_path, start[0], end[0])

    # Tracing through the path to check for malicious nodes
    lost = False
    for p in path:
        if p in mal:
            lost = True
            break
    if(lost == False):
        normal_delivered = 1
    else:
        normal_delivered = 0
    
    
    

    # -------Multipath Disjoint Dijkstra Simulation ------------
    Path_Arr = selectAllPaths(graph, start[0], end[0], 4)
    special_packets = 0
    special_recieved = 0
    lost = False
    for group in Path_Arr: # Going through groups in Path_Arr
        special_packets += len(group)
        group_num = 0
        for g in group: # Going through paths in group
            path_lost = False
            for part in g: # Going through nodes in path
                if part in mal:
                    path_lost = True
            if(path_lost == False):
                group_num += 1
                special_recieved += 1

        if(group_num == 0):
            lost = True
            break
        
    if(lost == False):
        special_delivered = 1
    
    else:
        special_delivered = 0
    
    return normal_delivered, special_delivered, special_packets, special_recieved
    

# nearestN returns a list of the N nearest node indexes along with their
# distances.
def nearestN(routersDict, index, xCoord, yCoord, N):
    nodes = []
    for r in routersDict:
        if r != index:
            nodes.append([r,
                              math.hypot(
                                  routersDict[r][0] - xCoord,
                                  routersDict[r][1] - yCoord)])

    nodes.sort(key=lambda x: x[1])
    return nodes[:N]


# isConnected returns true of the graph has a single component and false
# otherwise.
def isConnected(vertices, connections):
    edges = {}
    for conn in connections:

        if conn[0] not in edges:
            edges[conn[0]] = []
        edges[conn[0]].append(conn[1])

        if conn[1] not in edges:
            edges[conn[1]] = []
        edges[conn[1]].append(conn[0])

    colors = {}
    for v in vertices:
        colors[v] = "w"

    colors[1] = "g"
    count = 0
    queue = deque([1])
    while len(queue) != 0:
        u = queue.popleft()
        for v in edges[u]:
            if colors[v] == "w":
                colors[v] = "g"
                queue.append(v)
        colors[u] = "b"
        count = count + 1

    if count == len(vertices):
        return True
    else:
        return False


# Also from https://www.udacity.com/blog/2021/10/implementing-dijkstras-algorithm-in-python.html --- Dijkstra's algorithm
def dijkstra_algorithm(graph, start_node):
    unvisited_nodes = list(graph.get_nodes())
 
    # We'll use this dict to save the cost of visiting each node and update it as we move along the graph   
    shortest_path = {}
 
    # We'll use this dict to save the shortest known path to a node found so far
    previous_nodes = {}
 
    # We'll use max_value to initialize the "infinity" value of the unvisited nodes   
    max_value = sys.maxsize
    for node in unvisited_nodes:
        shortest_path[node] = max_value
    # However, we initialize the starting node's value with 0   
    shortest_path[start_node] = 0
    
    # The algorithm executes until we visit all nodes
    while unvisited_nodes:
        # The code block below finds the node with the lowest score
        current_min_node = None
        for node in unvisited_nodes: # Iterate over the nodes
            if current_min_node == None:
                current_min_node = node
            elif shortest_path[node] < shortest_path[current_min_node]:
                current_min_node = node
                
        # The code block below retrieves the current node's neighbors and updates their distances
        neighbors = graph.get_outgoing_edges(current_min_node)
        for neighbor in neighbors:
            tentative_value = shortest_path[current_min_node] + graph.value(current_min_node, neighbor)
            if tentative_value < shortest_path[neighbor]:
                shortest_path[neighbor] = tentative_value
                # We also update the best path to the current node
                previous_nodes[neighbor] = current_min_node
 
        # After visiting its neighbors, we mark the node as "visited"
        unvisited_nodes.remove(current_min_node)

    
    return previous_nodes, shortest_path
        

# From https://www.udacity.com/blog/2021/10/implementing-dijkstras-algorithm-in-python.html but edited for the purpose of this code
def return_result(previous_nodes, shortest_path, start_node, target_node):
    path = []
    node = target_node
    if node not in previous_nodes:
        return [], 0
    else:
        while node != start_node:
            path.append(node)
            node = previous_nodes[node]
        
        # Add the start node manually
        path.append(start_node)
        
        
        path.reverse()
        return path, shortest_path[target_node]


# Multipath Disjoint Dijkstra Routing
def selectAllPaths(graph, s, t, num_per):
    P = []
    currentPath = []
    nPaths = 1

    while True:
        if(nPaths > 1):
          graph.adjustWeights(P[(nPaths - 2)])

        
        previous_nodes, shortest_path = dijkstra_algorithm(graph, s)
        current_path, path_weight = return_result(previous_nodes, shortest_path, s, t)
        if(current_path == [s, t]):
            break
        
        if(len(current_path) != 0):
          nPaths += 1
          P.append(current_path)

        else:
          break


    random.shuffle(P)
    # Divide Into Groups of paths
    final = []
    while len(P) != 0:
        container = []
        for x in range(num_per):
          if(len(P) == 0):
              break
            
          else:
              container.append(P[0])
              P.pop(0)
        final.append(container)

    return final



if __name__ == "__main__":
    mal_num = 5
    normal_success = 0
    special_success = 0
    total_special_packets = 0
    special_made_it = 0
    for x in range(2000):
        normal, special, special_packets, special_recieved = main(mal_num)
        normal_success += normal
        special_success += special
        total_special_packets += special_packets
        special_made_it += special_recieved

    normal_delivery_ratio = normal_success/2000
    special_delivery_ratio = special_made_it/total_special_packets
    normal_success_rate = normal_success/2000
    special_success_rate = special_success/2000
    print("Network Config: 100 nodes, 10-20 connections per node, " + str(mal_num) + " malicious nodes.")
    print("Packet Delivery Ratios")
    print(normal_delivery_ratio)
    print(special_delivery_ratio)
    print("Success Ratios")
    print(normal_success_rate)
    print(special_success_rate)
    
