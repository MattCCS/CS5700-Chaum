"""
STUDENT: Matthew Cotton
TOPIC: CS5700 Final Project Proposal

ABSTRACT: For my final project, I would like to implement a TCP-layer
          Chaumian Mix network.

BACKGROUND: The purpose of a Mix network is to provide a level of
            confidentiality and anonymity to Internet traffic by routing
            traffic through servers called "mix nodes".  At each hop, the
            data packet -- which is initially encrypted with multiple
            different public keys -- has a layer of encryption stripped
            away.  Each "layer" of the data packet contains the next IP
            address hop along the path.  As a result, no single node knows
            the full intended path of the traffic, and so the compromise of
            one or a few nodes does not immediately compromise the
            confidentiality or anonymity of the participants.

PROPOSAL: I would like to implement a Mix network in Python.  I intend
          to run multiple "nodes" on one or more physical or
          virtual machines, where each node is assigned a public/private
          keypair.  I will then run multiple "communicants"
          (senders/receivers) who will send encrypted TCP packets through
          the network to transmit data, via randomly-chosen routes.
"""
