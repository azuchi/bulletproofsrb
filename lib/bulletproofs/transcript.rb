# frozen_string_literal: true

module Bulletproofs
  # Transcript class
  class Transcript
    attr_reader :dst, :points

    # Initialize transcript
    # @param [String] dst Domain separator tag.
    def initialize(dst = "")
      @dst = dst
      @points = []
    end

    # Calculate challenge.
    # @return [Integer] challenge value.
    def challenge_scalar(label)
      # TODO: use library like merlin
      payload = label
      payload +=
        points
          .map do |p|
            dst = p.is_a?(ECDSA::Point) ? p : p.to_affine
            ECDSA::Format::PointOctetString.encode(dst)
          end
          .join
      h = Digest::SHA256.digest(payload)
      h.unpack1("H*").hex % GROUP.order
    end
  end
end
