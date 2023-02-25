# frozen_string_literal: true

module Bulletproofs
  module RangeProof
    # Range proof base class
    class Base
      include Util

      attr_reader :v,
                  :p_a,
                  :p_s,
                  :p_t1,
                  :p_t2,
                  :tx,
                  :tx_bf,
                  :e,
                  :transcript,
                  :y,
                  :z,
                  :x

      def initialize(v, a, s, t1, t2, tx, tx_bf, e, dst: "")
        @v = v
        @p_a = a
        @p_s = s
        @p_t1 = t1
        @p_t2 = t2
        @tx = tx
        @tx_bf = tx_bf
        @e = e
        @transcript = Transcript.new(dst)
        @transcript.points << a
        @transcript.points << s
        @y = @transcript.challenge_scalar("y")
        @z = @transcript.challenge_scalar("z")
        @transcript.points << t1
        @transcript.points << t2
        @x = @transcript.challenge_scalar("x")
      end

      # Check whether this proof is valid or not.
      # @return [Boolean]
      def valid?
        raise NotImplementedError
      end

      # Compute tx commitment using tx and tx_bf.
      # @return [ECDSA::Point]
      def tx_commitment
        Commitment.create(tx_bf, tx)
      end

      def y_n
        @y_n ||= UPPER_EXP.times.map { |i| FIELD.power(y, i) }
      end

      def y_n_inv
        @y_n_inv ||= y_n.map { |y| FIELD.inverse(y) }
      end

      def zz
        @zz ||= FIELD.power(z, 2)
      end

      def xx
        @xx ||= FIELD.power(x, 2)
      end

      def vec_h
        @vec_h ||= UPPER_EXP.times.map { GENERATOR_H }
      end

      def vec_g
        @vec_g ||= UPPER_EXP.times.map { GENERATOR_G }
      end

      def vec_h2
        @vec_h2 ||= vec_h.zip(y_n_inv).map { |a, b| a * b }
      end

      def zz_powers
        @zz_powers ||= POWERS.map { |p| FIELD.mod(p * zz) }
      end

      def l1
        y_n
          .map { |y| FIELD.mod(y * z) }
          .zip(zz_powers)
          .map { |a, b| FIELD.mod(a + b) }
      end

      def l2
        UPPER_EXP
          .times
          .map { z }
          .zip(
            y_n_inv
              .map { |y| FIELD.mod(y * zz) }
              .zip(POWERS)
              .map { |a, b| FIELD.mod(a * b) }
          )
          .map { |a, b| FIELD.mod(a + b) }
      end

      # Check t() validity.
      # @return [Boolean]
      def valid_poly_t?
        lhs = tx_commitment
        # z^2V + δ(y, z)B + xT1 + x^2T2
        rhs =
          v * zz + GENERATOR_G * delta(y_n, z, ORDER) + p_t1 * x + p_t2 * xx
        lhs == rhs
      end

      def e_inv
        @e_inv ||= (GENERATOR_H * e).negate
      end

      def p1
        @p1 ||=
          e_inv + p_a + p_s * x +
            vec_h2.zip(l1).map { |a, b| a * b }.sum(GROUP.infinity) +
            vec_g.map { |v| v * z }.sum(GROUP.infinity).negate
      end

      def p2
        @p2 ||=
          e_inv + p_a + p_s * x +
            vec_h.zip(l2).map { |a, b| a * b }.sum(GROUP.infinity) +
            vec_g.map { |v| v * z }.sum(GROUP.infinity).negate
      end
    end
  end
end
