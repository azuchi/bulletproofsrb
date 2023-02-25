# frozen_string_literal: true

require "bulletproofs/version"
require "ecdsa"
require "securerandom"
require "json"

#  Bulletproof range proof protocol on the secp256k1 curve.
module Bulletproofs
  class Error < StandardError
  end

  autoload :Ext, "bulletproofs/ext"
  autoload :Util, "bulletproofs/util"
  autoload :Commitment, "bulletproofs/commitment"
  autoload :Transcript, "bulletproofs/transcript"
  autoload :RangeProof, "bulletproofs/range_proof"

  using Ext

  GROUP = ECDSA::Group::Secp256k1
  ORDER = GROUP.order
  ORDER_HEX = "0x#{ORDER.hex}"
  FIELD = ECDSA::PrimeField.new(ORDER)

  GENERATOR_G = GROUP.generator

  # NUMS point generated by sha256 hashing G
  GENERATOR_H =
    ECDSA::Point.new(
      GROUP,
      0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,
      0x31d3c6863973926e049e637cb1b5f40a36dac28af1766968c30c2313f3a38904
    )
  # NUMS point generated by sha256 hashing H
  GNERATOR_B =
    ECDSA::Point.new(
      GROUP,
      0x3de7e317f561e8c9481b2128508c7effd2d524528b7da29e14d040d86e4b0159,
      0xafd6259519fb77ba2b3bcb83a464cac183c85a2431539ad9a2ab41d7e06beeb2
    )
end
