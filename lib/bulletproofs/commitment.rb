# frozen_string_literal: true

module Bulletproofs
  # Perdersen Commitment
  module Commitment
    module_function

    # Create pedersen commitment(xG + vH).
    # @param [Integer] x Blind factor.
    # @param [Integer] v value
    # @return [ECDSA::Point] pedersen commitment
    # @raise [ArgumentError]
    def create(x, v)
      raise ArgumentError, "x must be integer" unless x.is_a?(Integer)
      raise ArgumentError, "v must be integer" unless v.is_a?(Integer)

      ECDSA::Group::Secp256k1.generator.multiply_by_scalar(v) +
        GNERATOR_H.multiply_by_scalar(x)
    end

    # Create vector pedersen commitment
    # @param [Array(Integer)] l vector
    # @param [Array(Integer)] r vector
    # @param [Integer] x Blind factor
    # @return [ECDSA::Point] Vector pedersen commitment
    def create_vector_pedersen(l, r, x)
      g = ECDSA::Group::Secp256k1.generator
      h = GNERATOR_H
      p1 =
        l[1..].inject(g.multiply_by_scalar(l.first)) do |result, f|
          result + g.multiply_by_scalar(f)
        end
      p2 =
        r[1..].inject(h.multiply_by_scalar(r.first)) do |result, f|
          result + h.multiply_by_scalar(f)
        end
      p1 + p2 + h.multiply_by_scalar(x)
    end
  end
end
