# frozen_string_literal: true
module Bulletproofs
  # Utility module
  module Util
    # Compute delta(y, z)
    # @param [Array(Integer)] y
    # @param [Integer] z
    # @return [Integer]
    def delta(y, z, mod = nil)
      two_pow = y.length.times.map { |i| mod ? 2.pow(i, mod) : 2.pow(i) }
      zz = mod ? z.pow(2, mod) : z.pow(2)
      zzz = mod ? z.pow(3, mod) : z.pow(3)
      left = (z - zz) * y.sum
      right = zzz * two_pow.sum
      result = left - right
      mod ? result % mod : result
    end
  end
end
