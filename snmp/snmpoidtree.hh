#ifndef SNMPOIDTREE_HH
#define SNMPOIDTREE_HH
#include <click/vector.hh>
#include "snmpbasics.hh"

class SNMPOidTree { public:

  struct Node;

  SNMPOidTree();
  ~SNMPOidTree();

  int find(const SNMPOid &) const;
  int find_prefix(const SNMPOid &, int *prefix_length) const;
  Node *insert(const SNMPOid &, int);

  void extract_oid(Node *, SNMPOid *) const;

  const Node *find_node(const SNMPOid &) const;
  Node *force_node(const SNMPOid &);
  static int node_data(const Node *n)		{ return n->data; }
  static void set_node_data(Node *n, int d)	{ n->data = d; }

  struct Node {
    uint32_t suffix;
    Node *parent;
    Node *sibling;
    Node *child;
    int data;
  };

 private:

  Node **_nodes;
  int _nnodes;
  int _nodes_cap;

  enum { NODES_PER_GROUP = 256 };

  SNMPOidTree(const SNMPOidTree &);
  SNMPOidTree &operator=(const SNMPOidTree &);
  
  Node *root_node() const;
  Node *alloc_node(uint32_t, Node *, Node *);
  
};

inline SNMPOidTree::Node *
SNMPOidTree::root_node() const
{
  assert(_nnodes > 0);
  return &(_nodes[0][0]);
}

inline int
SNMPOidTree::find(const SNMPOid &oid) const
{
  if (const Node *n = find_node(oid))
    return n->data;
  else
    return -1;
}

inline SNMPOidTree::Node *
SNMPOidTree::insert(const SNMPOid &oid, int data)
{
  Node *n = force_node(oid);
  if (n)
    n->data = data;
  return n;
}

#endif
