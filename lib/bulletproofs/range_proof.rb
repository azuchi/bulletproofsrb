# frozen_string_literal: true

module Bulletproofs
  # Range proof using Bulletproofs.
  module RangeProof
    using Ext
    include Util

    # The upper bound of the range proof.
    UPPER_EXP = 64
    # Powers of 2 up to upper bound
    POWERS = UPPER_EXP.times.map { |i| FIELD.power(2, i) }

    autoload :Base, "bulletproofs/range_proof/base"
    autoload :Uncompressed, "bulletproofs/range_proof/uncompressed"
    autoload :Compressed, "bulletproofs/range_proof/compressed"

    module_function

    # Compute uncompressed range proof for +v+.
    # @param [Bulletproofs::Transcript] transcript
    # @param [Integer] bf Blinding factor.
    # @param [Integer] v Value to be committed.
    def compute(transcript, bf, v)
      raise ArgumentError, "v grater than 2^64" if v > 2.pow(UPPER_EXP)
      raise ArgumentError, "v lower than 0" if v.negative?

      commitment = Commitment.create(bf, v).to_projective

      # convert value to binary
      binary = v.to_s(2).each_char.to_a.reverse.map(&:to_i)
      binary << 0 until binary.length == POWERS.length
      a_L = binary
      a_R = binary.map { |b| FIELD.mod(b - 1) }

      unless a_L.zip(a_R).map { |a, b| a * b }.sum.zero?
        raise Error, "a_L * a_R has to be 0"
      end

      # generate vector pedersen commitment
      a_bf = SecureRandom.random_number(ORDER)
      a_com = Commitment.create_vector_pedersen(a_L, a_R, a_bf).to_projective
      transcript.points << a_com

      # Prove 3 statements.
      # <a_L, POWERS> = v
      # <a_L, a_R> = 0
      # (a_L - 1) - a_R = 0

      # generate blind vector commitment
      s_L = POWERS.length.times.map { SecureRandom.random_number(ORDER) }
      s_R = POWERS.length.times.map { SecureRandom.random_number(ORDER) }
      s_bf = SecureRandom.random_number(ORDER)
      s_com = Commitment.create_vector_pedersen(s_L, s_R, s_bf).to_projective
      transcript.points << s_com

      # Calculate challenge y and z by H(st, A, S)
      y = transcript.challenge_scalar("y")
      y_n = a_L.length.times.map { |i| FIELD.power(y, i) }

      z = transcript.challenge_scalar("z")
      # z^2
      zz = FIELD.power(z, 2)
      zz_powers = POWERS.map { |p| FIELD.mod(p * zz) }

      # unblinded
      a_R_z = a_R.map { |r| FIELD.mod(r + z) }
      l0 = a_L.map { |l| FIELD.mod(l - z) }
      r0 =
        y_n
          .zip(a_R_z)
          .map { |a, b| FIELD.mod(a * b) }
          .zip(zz_powers)
          .map { |a, b| FIELD.mod(a + b) }

      # l(x) = l0 + l1x = (aL + sLx) - z
      l =
        lambda do |x|
          s_L_x = s_L.map { |s| FIELD.mod(s * x) }
          a_L
            .zip(s_L_x)
            .map { |a, b| FIELD.mod(a + b) }
            .map { |a| FIELD.mod(a - z) }
        end
      # r(x) = r0 + r1x = y^n * ((aR + sRx) + z) + z^2 * 2^n
      r =
        lambda do |x|
          s_R_x = s_R.map { |s| FIELD.mod(s * x) }
          tmp = a_R.zip(s_R_x).map { |a, b| FIELD.mod(a + b + z) }
          y_n
            .zip(tmp)
            .map { |a, b| FIELD.mod(a * b) }
            .zip(zz_powers)
            .map { |a, b| FIELD.mod(a + b) }
        end

      # t(x) = <l(x), r(x)> = t0 + t1x + t2x^2
      t =
        lambda do |x|
          FIELD.mod(
            l.call(x).zip(r.call(x)).map { |a, b| FIELD.mod(a * b) }.sum
          )
        end

      l1 = s_L.dup
      r1 = y_n.zip(s_R).map { |a, b| FIELD.mod(a * b) }
      t0 = FIELD.mod(l0.zip(r0).map { |a, b| FIELD.mod(a * b) }.sum)
      t2 = FIELD.mod(l1.zip(r1).map { |a, b| FIELD.mod(a * b) }.sum)
      t1 =
        FIELD.mod(
          l0
            .zip(l1)
            .map { |a, b| FIELD.mod(a + b) }
            .zip(r0.zip(r1).map { |a, b| FIELD.mod(a + b) })
            .map { |a, b| FIELD.mod(a * b) }
            .sum - t0 - t2
        )

      t1_bf = SecureRandom.random_number(ORDER)
      t2_bf = SecureRandom.random_number(ORDER)

      t1_com = Commitment.create(t1_bf, t1).to_projective
      t2_com = Commitment.create(t2_bf, t2).to_projective
      transcript.points << t1_com
      transcript.points << t2_com

      x = transcript.challenge_scalar("x")
      xx = FIELD.power(x, 2)
      tx = FIELD.mod(t0 + t1 * x + t2 * xx)
      tx_bf = FIELD.mod(zz * bf + x * t1_bf + xx * t2_bf)

      raise Error, "t(x) not match tx" unless t.call(x) == tx

      e = FIELD.mod(a_bf + x * s_bf)

      Uncompressed.new(
        commitment.to_affine,
        a_com.to_affine,
        s_com.to_affine,
        t1_com.to_affine,
        t2_com.to_affine,
        tx,
        tx_bf,
        e,
        l.call(x),
        r.call(x),
        dst: transcript.dst
      )
    end
  end
end
