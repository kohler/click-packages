/*
 * snmpoidtree.{cc,hh} -- SNMP OID tree
 * Eddie Kohler
 *
 * Copyright (c) 2001 ACIRI
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, subject to the conditions
 * listed in the Click LICENSE file. These conditions include: you must
 * preserve this copyright notice, and you cannot mention the copyright
 * holders in advertising related to the Software without their permission.
 * The Software is provided WITHOUT ANY WARRANTY, EXPRESS OR IMPLIED. This
 * notice is a summary of the Click LICENSE file; the license in that file is
 * legally binding.
 */

#include <click/config.h>
#include "snmpoidtree.hh"
#include <click/straccum.hh>
#include <click/error.hh>

SNMPOidTree::SNMPOidTree()
  : _nodes(0), _nnodes(0), _nodes_cap(0)
{
  if ((_nodes = new Node *[1]))
    if ((_nodes[0] = new Node[NODES_PER_GROUP]))
      _nodes_cap = NODES_PER_GROUP;
}

SNMPOidTree::~SNMPOidTree()
{
  for (int i = 0; i < _nodes_cap / NODES_PER_GROUP; i++)
    delete[] _nodes[i];
  delete[] _nodes;
}

SNMPOidTree::Node *
SNMPOidTree::alloc_node(uint32_t suffix, Node *parent, Node *sibling)
{
  if (_nnodes == _nodes_cap) {
    Node *new_group = new Node[NODES_PER_GROUP];
    Node **new_nodes = new Node *[(_nodes_cap / NODES_PER_GROUP) + 1];
    if (!new_group || !new_nodes) {
      delete[] new_group;
      delete[] new_nodes;
      return 0;
    }
    memcpy(new_nodes, _nodes, sizeof(Node *) * (_nodes_cap / NODES_PER_GROUP));
    _nodes[_nodes_cap / NODES_PER_GROUP] = new_group;
    delete[] _nodes;
    _nodes = new_nodes;
    _nodes_cap += NODES_PER_GROUP;
  }

  Node *n = &_nodes[_nnodes / NODES_PER_GROUP][_nnodes % NODES_PER_GROUP];
  _nnodes++;

  n->suffix = suffix;
  n->parent = parent;
  if (parent && !parent->child)
    parent->child = n;
  n->sibling = n->child = 0;
  n->data = -1;
  if (sibling)
    sibling->sibling = n;
  return n;
}

const SNMPOidTree::Node *
SNMPOidTree::find_node(const SNMPOid &oid) const
{
  if (_nnodes == 0 || oid.size() == 0)
    return 0;

  Node *np = root_node();
  int pos = 0;

  while (np && pos < oid.size()) {
    if (pos)
      np = np->child;
    uint32_t want = oid[pos];
    while (np && np->suffix != want)
      np = np->sibling;
    pos++;
  }

  return np;
}

int
SNMPOidTree::find_prefix(const SNMPOid &oid, int *prefix_len) const
{
  if (_nnodes == 0 || oid.size() == 0) {
    if (prefix_len) *prefix_len = 0;
    return -1;
  }

  Node *np = root_node();
  Node *prev = 0;
  int pos = 0;

  while (pos < oid.size()) {
    if (pos)
      np = np->child;
    uint32_t want = oid[pos];
    while (np && np->suffix != want)
      np = np->sibling;
    if (!np) {
      if (prefix_len) *prefix_len = pos;
      return (prev ? prev->data : -1);
    }
    prev = np;
    pos++;
  }

  if (prefix_len) *prefix_len = pos;
  return np->data;
}

SNMPOidTree::Node *
SNMPOidTree::force_node(const SNMPOid &oid)
{
  if (oid.size() == 0)
    return 0;
  if (_nnodes == 0 && !alloc_node(oid[0], 0, 0))
    return 0;

  Node *np = root_node();
  int pos = 0;

  while (pos < oid.size()) {
    if (pos) {
      if (np->child)
	np = np->child;
      else
	break;
    }
    uint32_t want = oid[pos];

    Node *prev = np;
    while (np && np->suffix != want)
      prev = np, np = np->sibling;

    if (!np && !(np = alloc_node(want, prev->parent, prev)))
      return 0;
    pos++;
  }

  while (pos < oid.size()) {
    if (!(np = alloc_node(oid[pos], np, 0)))
      return 0;
    pos++;
  }

  return np;
}

void
SNMPOidTree::extract_oid(Node *node, SNMPOid *oid) const
{
  int len = 0;
  for (Node *np = node; np; np = np->parent)
    len++;

  oid->resize(len);
  for (Node *np = node; np; np = np->parent)
    oid->unchecked_at(--len) = np->suffix;
}

ELEMENT_PROVIDES(SNMPOidTree)
ELEMENT_REQUIRES(SNMPOidInfo)
