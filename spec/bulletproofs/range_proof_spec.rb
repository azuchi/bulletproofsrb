# frozen_string_literal: true

require "spec_helper"

RSpec.describe Bulletproofs::RangeProof do
  describe "compute and verify" do
    it do
      transcript = Bulletproofs::Transcript.new("Range proof Test")
      blind_factor = 1_897_278_917_812_981_289_198
      value = 25
      commitment = Bulletproofs::Commitment.create(blind_factor, value)
      proof = described_class.compute(transcript, blind_factor, value)
    end
  end
end
