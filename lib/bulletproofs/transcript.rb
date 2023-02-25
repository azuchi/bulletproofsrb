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
        points.map { |p| ECDSA::Format::PointOctetString.encode(p) }.join
      h = Digest::SHA256.digest(payload)
      h.unpack1("H*").hex % GROUP.order
    end
  end
end
