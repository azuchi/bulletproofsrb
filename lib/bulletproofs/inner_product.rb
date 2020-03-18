module Bulletproofs

  module InnerProduct

    # Number of scalars that should remain at the end of a recursive proof.
    # The paper uses 2, by reducing the scalars as far as possible.
    # We stop one recursive step early, trading two points (L, R) for two scalars, which reduces verification and prover cost.
    IP_AB_SCALARS = 4

    module_function

    # Calculate proof size for +size+ elements.
    # @param [Integer] size number of elements in vector.
    # @return [Integer] proof size.
    def proof_length(size)
      return 32 * (1 + 2 * size) if (size < (IP_AB_SCALARS / 2))
      bit_count = size.popcount
      log = Math.log2(2 * size / IP_AB_SCALARS).floor
      32 * (1 + 2 * (bit_count - 1 + log) + IP_AB_SCALARS) + (2 * log + 7) / 8
    end

  end

end