# frozen_string_literal: true

require "bulletproofs/version"
require "matrix"
require "ecdsa"

#  Bulletproof range proof protocol on the secp256k1 curve.
module Bulletproofs
  class Error < StandardError
  end

  autoload :Commitment, "bulletproofs/commitment"
  autoload :Transcript, "bulletproofs/transcript"
  autoload :RangeProof, "bulletproofs/range_proof"
end
