# frozen_string_literal: true

module Bulletproofs
  # Range proof using Bulletproofs.
  class RangeProof
    using Ext
    include Util
    extend Util

    ORDER = ECDSA::Group::Secp256k1.order
    ORDER_HEX = "0x#{ORDER.hex}"
    FIELD = ECDSA::PrimeField.new(ORDER)

    # The upper bound of the range proof.
    UPPER_EXP = 64
    # Powers of 2 up to upper bound
    POWERS = UPPER_EXP.times.map { |i| FIELD.power(2, i) }

    attr_reader :v, :a, :s, :t1, :t2, :tx, :tx_bf, :e, :lx, :rx, :y, :z, :x

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
    def initialize(v, a, s, t1, t2, tx, tx_bf, e, lx, rx, dst: "")
      @v = v
      @a = a
      @s = s
      @t1 = t1
      @t2 = t2
      @tx = tx
      @tx_bf = tx_bf
      @e = e
      @lx = lx
      @rx = rx
      transcript = Transcript.new(dst)
      transcript.points << a
      transcript.points << s
      @y = transcript.challenge_scalar("y")
      @z = transcript.challenge_scalar("z")
      transcript.points << t1
      transcript.points << t2
      @x = transcript.challenge_scalar("x")
    end

    # Compute range proof for +v+.
    # @param [Bulletproofs::Transcript] transcript
    # @param [Integer] bf Blinding factor.
    # @param [Integer] v Value to be committed.
    def self.compute(transcript, bf, v)
      raise ArgumentError, "v grater than 2^64" if v > 2.pow(UPPER_EXP)
      raise ArgumentError, "v lower than 0" if v.negative?

      commitment = Commitment.create(bf, v)

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
      a_com = Commitment.create_vector_pedersen(a_L, a_R, a_bf)
      transcript.points << a_com

      # Prove 3 statements.
      # <a_L, POWERS> = v
      # <a_L, a_R> = 0
      # (a_L - 1) - a_R = 0

      # generate blind vector commitment
      s_L = POWERS.length.times.map { SecureRandom.random_number(ORDER) }
      s_R = POWERS.length.times.map { SecureRandom.random_number(ORDER) }
      s_bf = SecureRandom.random_number(ORDER)
      s_com = Commitment.create_vector_pedersen(s_L, s_R, s_bf)
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

      t1_com = Commitment.create(t1_bf, t1)
      t2_com = Commitment.create(t2_bf, t2)
      transcript.points << t1_com
      transcript.points << t2_com

      x = transcript.challenge_scalar("x")
      xx = FIELD.power(x, 2)
      tx = FIELD.mod(t0 + t1 * x + t2 * xx)
      tx_bf = FIELD.mod(zz * bf + x * t1_bf + xx * t2_bf)

      raise Error, "t(x) not match tx" unless t.call(x) == tx

      e = FIELD.mod(a_bf + x * s_bf)

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
        r.call(x),
        dst: transcript.dst
      )
    end

    # Check whether this range proof is valid or not.
    # @return [Boolean]
    def valid?
      y_n = UPPER_EXP.times.map { |i| FIELD.power(y, i) }
      y_n_inv = y_n.map { |y| FIELD.inverse(y) }
      zz = FIELD.power(z, 2)
      xx = FIELD.power(x, 2)

      # Check tx = <lx, rx>
      unless FIELD.mod(lx.zip(rx).map { |a, b| FIELD.mod(a * b) }.sum) == tx
        return false
      end

      lhs = Commitment.create(tx_bf, tx)
      # z^2V + δ(y, z)B + xT1 + x^2T2
      rhs =
        v * zz + ECDSA::Group::Secp256k1.generator * delta(y_n, z, ORDER) +
          t1 * x + t2 * xx
      return false unless lhs == rhs

      vec_h = UPPER_EXP.times.map { GNERATOR_H }
      vec_g = UPPER_EXP.times.map { ECDSA::Group::Secp256k1.generator }
      vec_h2 = vec_h.zip(y_n_inv).map { |a, b| a * b }

      zz_powers = POWERS.map { |p| FIELD.mod(p * zz) }
      l1 =
        y_n
          .map { |y| FIELD.mod(y * z) }
          .zip(zz_powers)
          .map { |a, b| FIELD.mod(a + b) }
      l2 =
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

      e_inv = (GNERATOR_H * e).negate
      p1 =
        e_inv + a + s * x +
          vec_h2
            .zip(l1)
            .map { |a, b| a * b }
            .sum(ECDSA::Group::Secp256k1.infinity) +
          vec_g.map { |v| v * z }.sum(ECDSA::Group::Secp256k1.infinity).negate
      p2 =
        e_inv + a + s * x +
          vec_h
            .zip(l2)
            .map { |a, b| a * b }
            .sum(ECDSA::Group::Secp256k1.infinity) +
          vec_g.map { |v| v * z }.sum(ECDSA::Group::Secp256k1.infinity).negate
      p =
        vec_g
          .zip(lx)
          .map { |a, b| a * b }
          .zip(vec_h2.zip(rx).map { |a, b| a * b })
          .map { |a, b| a + b }
          .sum(ECDSA::Group::Secp256k1.infinity)

      p1 == p2 && p2 == p
    end

    def to_h
      {
        V: v.hex,
        A: a.hex,
        S: s.hex,
        T1: t1.hex,
        T2: t2.hex,
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
        G: ECDSA::Group::Secp256k1.generator.hex,
        order: ORDER_HEX
      }
    end

    # Load uncompressed proof from json string.
    # @param [String] json_str json string.
    # @return [Bulletproofs::RangeProof]
    def self.from_json(json_str)
      json = JSON.parse(json_str)
      unless json["G"] == ECDSA::Group::Secp256k1.generator.hex
        raise ArgumentError, "Unsupported generator specified"
      end
      unless json["order"] == ORDER_HEX
        raise ArgumentError, "Unsupported order specified"
      end

      v =
        ECDSA::Format::PointOctetString.decode(
          [json["V"]].pack("H*"),
          ECDSA::Group::Secp256k1
        )
      a =
        ECDSA::Format::PointOctetString.decode(
          [json["A"]].pack("H*"),
          ECDSA::Group::Secp256k1
        )
      s =
        ECDSA::Format::PointOctetString.decode(
          [json["S"]].pack("H*"),
          ECDSA::Group::Secp256k1
        )
      t1 =
        ECDSA::Format::PointOctetString.decode(
          [json["T1"]].pack("H*"),
          ECDSA::Group::Secp256k1
        )
      t2 =
        ECDSA::Format::PointOctetString.decode(
          [json["T2"]].pack("H*"),
          ECDSA::Group::Secp256k1
        )
      tx = json["tx"].hex
      tx_bf = json["txbf"].hex
      e = json["e"].hex
      lx = json["lx"]["elems"].map(&:hex)
      rx = json["rx"]["elems"].map(&:hex)
      RangeProof.new(v, a, s, t1, t2, tx, tx_bf, e, lx, rx)
    end
  end
end
