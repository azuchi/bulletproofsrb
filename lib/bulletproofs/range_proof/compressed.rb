# frozen_string_literal: true

module Bulletproofs
  module RangeProof
    # Compressed proof.
    class Compressed < Base
      using Bulletproofs::Ext

      attr_reader :a0, :b0, :terms, :w

      # @param [ECDSA::Point] v Pedersen commitment.
      # @param [ECDSA::Point] a Vector pedersen commitment committing to a_L and a_R
      # @param [ECDSA::Point] s Vector pedersen commitment committing to s_L and s_R
      # @param [ECDSA::Point] t1 Pedersen commitment to tx
      # @param [ECDSA::Point] t2 Pedersen commitment to tx^2
      # @param [Integer] tx Polynomial t() evaluated with challenge x
      # @param [Integer] tx_bf Opening blinding factor for t() to verify the correctness of t(x)
      # @param [Integer] e Opening e of the combined blinding factors using in A and S to verify correctness of l(x) and r(x)
      # @param [Array(Integer)] a0 Left side of the blinded vector product
      # @param [Array(Integer)] b0 Right side of the blinded vector product
      # @param [Array] terms
      # @param [String] dst Domain separation tag using transcript.
      def initialize(v, a, s, t1, t2, tx, tx_bf, e, a0, b0, terms, dst: "")
        super(v, a, s, t1, t2, tx, tx_bf, e, dst: dst)
        @a0 = a0
        @b0 = b0
        @terms = terms
        @w = transcript.challenge_scalar("w")
      end

      # Check whether this compressed proof is valid or not?
      # @return [Boolean]
      def valid?
        return false unless valid_poly_t?
        return false unless p1 == p2
        ts = transcript.dup

        # check tx = <lx, rx> using inner product proof
        uks = []
        terms.each do |term|
          ts.points << term[:L]
          ts.points << term[:R]
          uks << ts.challenge_scalar("uk")
        end

        q = GENERATOR_BP * w
        lhs = p1 + q * tx
        l0 = terms.first[:L]
        r0 = terms.first[:R]
        u0 = uks.first
        u02 = FIELD.power(u0, 2)
        u02_inv = FIELD.inverse(u02)
        g_sum = vec_g.dup
        h_sum = vec_h2.dup
        i = 0
        until g_sum.length == 1
          g_hi = []
          g_lo = []
          h_hi = []
          h_lo = []
          half = g_sum.length / 2
          g_sum.each.with_index do |g, j|
            if j < half
              g_lo << g
              h_lo << h_sum[j]
            else
              g_hi << g
              h_hi << h_sum[j]
            end
          end
          g_sum = []
          h_sum = []
          u = uks[i]
          u_inv = FIELD.inverse(u)
          g_lo.each.with_index do |g, j|
            g_sum << (g * u_inv + g_hi[j] * u)
            h_sum << (h_lo[j] * u + h_hi[j] * u_inv)
          end
          i += 1
        end

        det = l0 * u02 + r0 * u02_inv
        terms[1..]
          .each
          .with_index(1) do |t, j|
            uj2 = FIELD.power(uks[j], 2)
            uj2_inv = FIELD.inverse(uj2)
            det = det + t[:L] * uj2 + t[:R] * uj2_inv
          end

        g0 = g_sum.first
        h0 = h_sum.first
        a0_b0 = FIELD.mod(a0 * b0)

        rhs = g0 * a0 + h0 * b0 + q * a0_b0 + det.negate
        lhs == rhs
      end
    end
  end
end
