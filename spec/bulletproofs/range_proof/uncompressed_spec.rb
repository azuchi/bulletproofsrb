# frozen_string_literal: true

require "spec_helper"

RSpec.describe Bulletproofs::RangeProof::Uncompressed do
  describe "#to_json/load_json" do
    it do
      json_str = load_fixture("uncompressed_proof.json")
      proof = described_class.from_json(json_str)
      expect(proof.to_h.to_json).to eq(json_str)
    end
  end
end
