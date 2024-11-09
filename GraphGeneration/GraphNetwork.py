import networkx as nx

testGraph = nx.DiGraph()
testGraph.add_edge("A", "B")
testGraph.add_edge("B", "C")
testGraph.add_edge("A", "C")

nodePos = {"A": (0,0), "B": (1,0), "C": (2,0)}

nx.write_adjlist(testGraph, "out.txt", delimiter=' ')

nx.draw_networkx_nodes(testGraph, pos=nodePos, node_size=500)
nx.draw_networkx_edges(testGraph, pos=nodePos, arrowstyle='-')
