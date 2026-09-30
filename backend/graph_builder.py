import networkx as nx
from correlator import IncidentChain

def build_attack_graph(chain: IncidentChain) -> dict:
    """
    Converts an IncidentChain into a NetworkX directed graph and exports to JSON format 
    suitable for frontend libraries like React Flow or Cytoscape.
    """
    G = nx.DiGraph()
    
    # Track the previous node we added to draw sequential edges where appropriate
    prev_node = None
    
    for c_event in chain.events:
        evt = c_event.event
        
        # Determine main actor node (usually user or source IP)
        actor_id = evt.user if evt.user else evt.source_ip
        if actor_id:
            node_type = "user" if evt.user else "ip"
            if not G.has_node(actor_id):
                G.add_node(actor_id, label=actor_id, type=node_type)
        
        # Determine target node (host or dest IP)
        target_id = evt.host if evt.host else evt.dest_ip
        if target_id:
            node_type = "host" if evt.host else "ip"
            if not G.has_node(target_id):
                G.add_node(target_id, label=target_id, type=node_type)
                
        # If we have both actor and target, create an edge
        if actor_id and target_id:
            G.add_edge(actor_id, target_id, 
                       id=evt.event_id,
                       label=f"{evt.source}:{evt.event_type}",
                       timestamp=evt.timestamp.isoformat(),
                       stage=c_event.stage,
                       reason=c_event.link_reason)
            prev_node = target_id
        elif actor_id and prev_node and actor_id != prev_node:
            # Connect to previous node if it makes sense (e.g. lateral movement)
            G.add_edge(prev_node, actor_id,
                       id=evt.event_id,
                       label=f"{evt.source}:{evt.event_type}",
                       timestamp=evt.timestamp.isoformat(),
                       stage=c_event.stage)
            prev_node = actor_id
        elif target_id:
            prev_node = target_id
            
    # Export using NetworkX standard node-link format
    return nx.node_link_data(G)
