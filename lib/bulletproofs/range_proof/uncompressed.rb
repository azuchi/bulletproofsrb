# frozen_string_literal: true

module Bulletproofs
  module RangeProof
    # Uncompressed range proof.
    class Uncompressed
      using Bulletproofs::Ext
      include Util

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

      # The content of the proof is made into a Hash object.
      # @return [Hash]
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
        Uncompressed.new(v, a, s, t1, t2, tx, tx_bf, e, lx, rx)
      end
    end
  end
end
