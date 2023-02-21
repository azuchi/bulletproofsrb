# frozen_string_literal: true

require "spec_helper"

RSpec.describe Bulletproofs::RangeProof do
  describe "compute and verify" do
    it do
      transcript = Bulletproofs::Transcript.new("Range proof Test")
      blind_factor = 1_897_278_917_812_981_289_198
      value = 25
      proof = described_class.compute(transcript, blind_factor, value)
      expect(proof.valid?).to be true
    end
  end

  describe "#to_json/load_json" do
    it do
      json_str = load_fixture("uncompressed_proof.json")
      proof = described_class.from_json(json_str)
      expect(proof.to_h.to_json).to eq(json_str)
    end
  end
end
