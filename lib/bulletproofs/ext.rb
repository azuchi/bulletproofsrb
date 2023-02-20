# frozen_string_literal: true

module Bulletproofs
  # Extension of existing classes used within this library
  module Ext
    refine Integer do
      # Convert to hex string.
      # @return [String]
      def hex
        v = to_s(16)
        v.length.even? ? v : "0#{v}"
      end
    end

    refine ECDSA::Point do
      # Convert to hex string.
      # @param [Boolean] compressed Whether compressed format or not.
      # @return [String]
      def hex(compressed: true)
        ops = { compression: compressed }
        ECDSA::Format::PointOctetString.encode(self, ops).unpack1("H*")
      end
    end
  end
end
