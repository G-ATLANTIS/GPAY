'use strict';

const crypto = require('node:crypto');
const { sha256 } = require('./canonical');
const { normalizeCluster, signProposal } = require('./ha-quorum');
const { proposalSlot } = require('./ha-vote-store');

function publicBindingFromPrivate(privateKey) {
  let publicKey;
  try { publicKey = crypto.createPublicKey(privateKey); }
  catch { throw new Error('ha_signer_private_key_invalid'); }
  if (publicKey.asymmetricKeyType !== 'ed25519') throw new Error('ha_signer_private_key_type_must_be_ed25519');
  return sha256(publicKey.export({ type: 'spki', format: 'der' }));
}

class HADurableSigner {
  constructor({ cluster, node_id, private_key, vote_store, clock = () => Date.now() } = {}) {
    this.cluster = normalizeCluster(cluster);
    this.nodeId = String(node_id || '').toUpperCase();
    this.node = this.cluster.nodes.find(node => node.node_id === this.nodeId && node.role === 'VOTER' && node.status === 'ACTIVE');
    if (!this.node) throw new Error('ha_signer_node_not_active_voter');
    if (!vote_store || typeof vote_store.reserve !== 'function' || typeof vote_store.verify !== 'function') throw new Error('ha_signer_vote_store_required');
    if (vote_store.nodeId !== this.nodeId) throw new Error('ha_signer_vote_store_node_mismatch');
    if (typeof clock !== 'function') throw new Error('ha_signer_clock_invalid');
    const privateBinding = publicBindingFromPrivate(private_key);
    if (privateBinding !== this.node.public_key_binding_sha256) throw new Error('ha_signer_private_key_binding_mismatch');
    this.privateKey = private_key;
    this.voteStore = vote_store;
    this.clock = clock;
  }

  sign(proposal, { signed_at = null } = {}) {
    if (!proposal || !proposal.proposal_sha256) throw new Error('ha_signer_proposal_required');
    if (proposal.cluster_sha256 !== this.cluster.cluster_sha256 || proposal.cluster_epoch !== this.cluster.cluster_epoch) throw new Error('ha_signer_proposal_cluster_mismatch');

    let timestamp = signed_at;
    if (timestamp === null) {
      const slot = proposalSlot(proposal);
      const existing = this.voteStore.verify().rows.find(row => row.slot_key === slot);
      if (existing && existing.proposal_sha256 === proposal.proposal_sha256) timestamp = existing.signed_at;
      else timestamp = new Date(this.clock()).toISOString();
    }

    return signProposal({
      proposal,
      node_id: this.nodeId,
      private_key: this.privateKey,
      signed_at: timestamp,
      vote_store: this.voteStore,
    });
  }

  verifyJournal() {
    return this.voteStore.verify();
  }
}

module.exports = { HADurableSigner, publicBindingFromPrivate };
