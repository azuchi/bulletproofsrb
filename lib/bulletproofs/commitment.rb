# frozen_string_literal: true

module Bulletproofs
  # Pedersen Commitment
  module Commitment
    module_function

    # Create pedersen commitment(xG + vH).
    # @param [Integer] x Blind factor.
    # @param [Integer] v value
    # @return [ECDSA::Ext::JacobianPoint] pedersen commitment
    # @raise [ArgumentError]
    def create(x, v)
      raise ArgumentError, "x must be integer" unless x.is_a?(Integer)
      raise ArgumentError, "v must be integer" unless v.is_a?(Integer)
      raise ArgumentError, "x must be positive" unless x.positive?
      raise ArgumentError, "v must be positive" unless v.positive?

      GENERATOR_GJ * v + GENERATOR_HJ * x
    end

    # Create vector pedersen commitment
    # @param [Array(Integer)] l vector
    # @param [Array(Integer)] r vector
    # @param [Integer] x Blind factor
    # @return [ECDSA::Ext::JacobianPoint] Vector pedersen commitment
    def create_vector_pedersen(l, r, x)
      g = GENERATOR_GJ
      h = GENERATOR_HJ
      p1 = l.inject(INFINITY_J) { |result, f| result + g * f }
      p2 = r.inject(INFINITY_J) { |result, f| result + h * f }
      p1 + p2 + h * x
    end
  end
end
