# frozen_string_literal: true

require "spec_helper"

RSpec.describe Bulletproofs::Commitment do
  describe "#create" do
    it do
      expect(described_class.create(123, 1025)).to be_a(
        ECDSA::Ext::JacobianPoint
      )
    end

    context "when bf not integer" do
      it do
        expect { described_class.create("123", 1025) }.to raise_error(
          ArgumentError,
          "x must be integer"
        )
      end
    end

    context "when value not integer" do
      it do
        expect { described_class.create(123, "1025") }.to raise_error(
          ArgumentError,
          "v must be integer"
        )
      end
    end

    context "when x is negative" do
      it do
        expect { described_class.create(-1, 1025) }.to raise_error(
          ArgumentError,
          "x must be positive"
        )
      end
    end

    context "when v is negative" do
      it do
        expect { described_class.create(123, -1) }.to raise_error(
          ArgumentError,
          "v must be positive"
        )
      end
    end
  end
end
