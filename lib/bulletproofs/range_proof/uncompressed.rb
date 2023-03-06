# frozen_string_literal: true

module Bulletproofs
  module RangeProof
    # Uncompressed range proof.
    class Uncompressed < Base
      using Bulletproofs::Ext

      attr_reader :lx, :rx

      # @param [ECDSA::Point] v Pedersen commitment.
      # @param [ECDSA::Point] a Vector pedersen commitment committing to a_L and a_R
      # @param [ECDSA::Point] s Vector pedersen commitment committing to s_L and s_R
      # @param [ECDSA::Point] t1 Pedersen commitment to tx
      # @param [ECDSA::Point] t2 Pedersen commitment to tx^2
      # @param [Integer] tx Polynomial t() evaluated with challenge x
      # @param [Integer] tx_bf Opening blinding factor for t() to verify the correctness of t(x)
      # @param [Integer] e Opening e of the combined blinding factors using in A and S to verify correctness of l(x) and r(x)
      # @param [Array(Integer)] lx Left side of the blinded vector product
      # @param [Array(Integer)] rx Right side of the blinded vector product
      # @param [String] dst Domain separation tag using transcript.
      def initialize(v, a, s, t1, t2, tx, tx_bf, e, lx, rx, dst: "")
        super(v, a, s, t1, t2, tx, tx_bf, e, dst: dst)
        @lx = lx
        @rx = rx
      end

      # Check whether this range proof is valid or not.
      # @return [Boolean]
      def valid?
        # Check tx = <lx, rx>
        unless FIELD.mod(lx.zip(rx).map { |a, b| FIELD.mod(a * b) }.sum) == tx
          return false
        end

        return false unless valid_poly_t?

        p =
          vec_g
            .zip(lx)
            .map { |a, b| a * b }
            .zip(vec_h2.zip(rx).map { |a, b| a * b })
            .map { |a, b| a + b }
            .sum(GROUP.infinity)

        p1 == p2 && p2 == p
      end

      # The content of the proof is made into a Hash object.
      # @return [Hash]
      def to_h
        {
          V: v.hex,
          A: p_a.hex,
          S: p_s.hex,
          T1: p_t1.hex,
          T2: p_t2.hex,
          tx: "0x#{tx.hex}",
          txbf: "0x#{tx_bf.hex}",
          e: "0x#{e.hex}",
          lx: {
            n: ORDER_HEX,
            elems: lx.map { |x| "0x#{x.hex}" }
          },
          rx: {
            n: ORDER_HEX,
            elems: rx.map { |x| "0x#{x.hex}" }
          },
          G: GENERATOR_G.hex,
          order: ORDER_HEX
        }
      end

      # Load uncompressed proof from json string.
      # @param [String] json_str json string.
      # @return [Bulletproofs::RangeProof]
      def self.from_json(json_str)
        json = JSON.parse(json_str)
        unless json["G"] == GENERATOR_G.hex
          raise ArgumentError, "Unsupported generator specified"
        end
        unless json["order"] == ORDER_HEX
          raise ArgumentError, "Unsupported order specified"
        end

        v = ECDSA::Point.from_hex(json["V"], GROUP)
        a = ECDSA::Point.from_hex(json["A"], GROUP)
        s = ECDSA::Point.from_hex(json["S"], GROUP)
        t1 = ECDSA::Point.from_hex(json["T1"], GROUP)
        t2 = ECDSA::Point.from_hex(json["T2"], GROUP)
        tx = json["tx"].hex
        tx_bf = json["txbf"].hex
        e = json["e"].hex
        lx = json["lx"]["elems"].map(&:hex)
        rx = json["rx"]["elems"].map(&:hex)
        Uncompressed.new(v, a, s, t1, t2, tx, tx_bf, e, lx, rx)
      end

      # Convert compressed range proof using inner product.
      # @return [Bulletproofs::RangeProof::Compressed]
      def to_compress
        a = lx.dup
        b = rx.dup
        ts = transcript.dup
        w = ts.challenge_scalar("w")
        q = GENERATOR_BJ * w

        a_sum = a.dup
        b_sum = b.dup
        g_sum = vec_g.dup
        h_sum = vec_h2.dup

        terms = []
        until a_sum.length == 1
          a_lo = []
          b_lo = []
          g_lo = []
          h_lo = []
          a_hi = []
          b_hi = []
          g_hi = []
          h_hi = []
          half = a_sum.length / 2
          a_sum.each.with_index do |_, i|
            if i < half
              a_lo << a_sum[i]
              b_lo << b_sum[i]
              g_lo << g_sum[i]
              h_lo << h_sum[i]
            else
              a_hi << a_sum[i]
              b_hi << b_sum[i]
              g_hi << g_sum[i]
              h_hi << h_sum[i]
            end
          end
          alo_bhi = a_lo.zip(b_hi).map { |x, y| FIELD.mod(x * y) }.sum
          ahi_blo = a_hi.zip(b_lo).map { |x, y| FIELD.mod(x * y) }.sum

          l_k =
            g_hi.zip(a_lo).map { |x, y| x * y }.sum(INFINITY_J) +
              h_lo.zip(b_hi).map { |x, y| x * y }.sum(INFINITY_J) + q * alo_bhi
          r_k =
            g_lo.zip(a_hi).map { |x, y| x * y }.sum(INFINITY_J) +
              h_hi.zip(b_lo).map { |x, y| x * y }.sum(INFINITY_J) + q * ahi_blo

          ts.points << l_k
          ts.points << r_k
          uk = ts.challenge_scalar("uk")
          uk_inv = FIELD.inverse(uk)
          terms << { L: l_k, R: r_k }

          a_sum = []
          b_sum = []
          g_sum = []
          h_sum = []
          a_lo.each.with_index do |_, i|
            a_sum << (a_lo[i] * uk + a_hi[i] * uk_inv)
            b_sum << (b_lo[i] * uk_inv + b_hi[i] * uk)
            g_sum << (g_lo[i] * uk_inv + g_hi[i] * uk)
            h_sum << (h_lo[i] * uk + h_hi[i] * uk_inv)
          end
        end

        a0 = a_sum.first
        b0 = b_sum.first

        Compressed.new(v, p_a, p_s, p_t1, p_t2, tx, tx_bf, e, a0, b0, terms)
      end
    end
  end
end
