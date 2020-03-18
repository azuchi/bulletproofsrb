require 'spec_helper'

RSpec.describe Bulletproofs::InnerProduct do

  describe '#proof_length' do
    it 'should calculate proof size.' do
      expect(Bulletproofs::InnerProduct.proof_length(0)).to eq(32)
      expect(Bulletproofs::InnerProduct.proof_length(1)).to eq(96)
      expect(Bulletproofs::InnerProduct.proof_length(2)).to eq(160)
      expect(Bulletproofs::InnerProduct.proof_length(4)).to eq(225)
      expect(Bulletproofs::InnerProduct.proof_length(8)).to eq(289)
    end
  end

end