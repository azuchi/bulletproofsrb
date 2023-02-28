# frozen_string_literal: true

module Bulletproofs
  # Pedersen Commitment
  module Commitment
    module_function

    # Create pedersen commitment(xG + vH).
    # @param [Integer] x Blind factor.
    # @param [Integer] v value
    # @return [ECDSA::Ext::ProjectivePoint] pedersen commitment
    # @raise [ArgumentError]
    def create(x, v)
      raise ArgumentError, "x must be integer" unless x.is_a?(Integer)
      raise ArgumentError, "v must be integer" unless v.is_a?(Integer)

      GENERATOR_GP * v + GENERATOR_HP * x
    end

    # Create vector pedersen commitment
    # @param [Array(Integer)] l vector
    # @param [Array(Integer)] r vector
    # @param [Integer] x Blind factor
    # @return [ECDSA::Ext::ProjectivePoint] Vector pedersen commitment
    def create_vector_pedersen(l, r, x)
      g = GENERATOR_GP
      h = GENERATOR_HP
      p1 = l.inject(INFINITY_P) { |result, f| result + g * f }
      p2 = r.inject(INFINITY_P) { |result, f| result + h * f }
      p1 + p2 + h * x
    end
  end
end
