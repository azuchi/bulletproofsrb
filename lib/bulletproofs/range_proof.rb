# frozen_string_literal: true

require "securerandom"

module Bulletproofs
  # Range proof using Bulletproofs.
  class RangeProof
    # The upper bound of the range proof.
    UPPER_EXP = 64
    # Powers of 2 up to upper bound
    POWERS = UPPER_EXP.times.map { |i| 2.pow(i) }

    attr_reader :commitment, :a, :s, :t1, :t2, :tx, :tx_bf, :e, :lx, :rx

    # @param [ECDSA::Point] commitment Pedersen commitment.
    # @param [ECDSA::Point] a Vector pedersen commitment committing to a_L and a_R
    # @param [ECDSA::Point] s Vector pedersen commitment committing to s_L and s_R
    # @param [ECDSA::Point] t1 Pedersen commitment to tx
    # @param [ECDSA::Point] t2 Pedersen commitment to tx^2
    # @param [Integer] tx Polynomial t() evaluated with challenge x
    # @param [Integer] tx_bf Opening blinding factor for t() to verify the correctness of t(x)
    # @param [Integer] e Opening e of the combined blinding factors using in A and S to verify correctness of l(x) and r(x)
    # @param [Array(Integer)] lx Left side of the blinded vector product
    # @param [Array(Integer)] rx Right side of the blinded vector product
    def initialize(commitment, a, s, t1, t2, tx, tx_bf, e, lx, rx)
      @commitment = commitment
      @a = a
      @s = s
      @t1 = t1
      @t2 = t2
      @tx = tx
      @tx_bf = tx_bf
      @e = e
      @lx = lx
      @rx = rx
    end

    # Compute range proof for +v+.
    # @param [Bulletproofs::Transcript] transcript
    # @param [Integer] bf Blinding factor.
    # @param [Integer] v Value to be committed.
    def self.compute(transcript, bf, v)
      raise ArgumentError, "v grater than 2^64" if v > 2.pow(UPPER_EXP)
      raise ArgumentError, "v lower than 0" if v.negative?

      order = ECDSA::Group::Secp256k1.order
      commitment = Commitment.create(bf, v)

      # convert value to binary
      binary = v.to_s(2).each_char.to_a.reverse.map(&:to_i)
      binary << 0 until binary.length == POWERS.length
      a_L = binary
      a_R = binary.map { |b| (b - 1) % order }

      # generate vector pedersen commitment
      a_bf = SecureRandom.random_number(order)
      a_com = Commitment.create_vector_pedersen(a_L, a_R, a_bf)
      transcript.points << a_com

      # Prove 3 statements.
      # <a_L, POWERS> = v
      # <a_L, a_R> = 0
      # (a_L - 1) - a_R = 0

      # generate blind vector commitment
      s_L = POWERS.length.times.map { SecureRandom.random_number(order) }
      s_R = POWERS.length.times.map { SecureRandom.random_number(order) }
      s_bf = SecureRandom.random_number(order)
      s_com = Commitment.create_vector_pedersen(s_L, s_R, s_bf)
      transcript.points << s_com

      # Calculate challenge y and z by H(st, A, S)
      y = transcript.challenge_scalar("y")

      y_n = a_L.length.times.map { |i| y.pow(i, order) }
      z = transcript.challenge_scalar("z")

      # z^2
      zz = z.pow(2, order)
      zz_powers = POWERS.map { |p| (p * zz) % order }

      # unblinded
      a_R_z = a_R.map { |r| (r + z) % order }
      l0 = a_L.map { |l| (l - z) % order }
      r0 =
        y_n
          .zip(a_R_z)
          .map { |a, b| (a * b) % order }
          .zip(zz_powers)
          .map { |a, b| (a + b) % order }

      # l(x) = l0 + l1x = (aL + sLx) - z
      l =
        lambda do |x|
          s_L_x = s_L.map { |s| (s * x) % order }
          a_L
            .zip(s_L_x)
            .map { |a, b| (a + b) % order }
            .map { |a| (a - z) % order }
        end
      # r(x) = r0 + r1x = y^n * ((aR + sRx) + z) + z^2 * 2^n
      r =
        lambda do |x|
          s_R_x = s_R.map { |s| (s * x) % order }
          tmp = a_R.zip(s_R_x).map { |a, b| (a + b + z) % order }
          y_n
            .zip(tmp)
            .map { |a, b| (a * b) % order }
            .zip(zz_powers)
            .map { |a, b| (a + b) % order }
        end

      # t(x) = <l(x), r(x)> = t0 + t1x + t2x^2
      t =
        lambda do |x|
          l.call(x).zip(r.call(x)).map { |a, b| (a * b) % order }.sum % order
        end

      l1 = s_L.dup
      r1 = y_n.zip(s_R).map { |a, b| (a * b) % order }
      t0 = l0.zip(r0).map { |a, b| (a * b) % order }.sum % order
      t2 = l1.zip(r1).map { |a, b| (a * b) % order }.sum % order
      t1 =
        (
          l0
            .zip(l1)
            .map { |a, b| (a + b) % order }
            .zip(r0.zip(r1).map { |a, b| (a + b) % order })
            .map { |a, b| (a * b) % order }
            .sum - t0 - t2
        ) % order

      t1_bf = SecureRandom.random_number(order)
      t2_bf = SecureRandom.random_number(order)

      t1_com = Commitment.create(t1_bf, t1)
      t2_com = Commitment.create(t2_bf, t2)
      transcript.points << t1_com
      transcript.points << t2_com

      x = transcript.challenge_scalar("x")
      xx = x.pow(2, order)
      tx = (t0 + t1 * x + t2 * xx) % order
      tx_bf = (zz * bf + x * t1_bf + xx * t2_bf) % order

      raise Error, "t(x) not match tx" unless t.call(x) == tx

      e = (a_bf + x * s_bf) & order

      RangeProof.new(
        commitment,
        a_com,
        s_com,
        t1_com,
        t2_com,
        tx,
        tx_bf,
        e,
        l.call(x),
        r.call(x)
      )
    end
  end
end
