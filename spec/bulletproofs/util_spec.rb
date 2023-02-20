# frozen_string_literal: true

require "spec_helper"

RSpec.describe Bulletproofs::Util do
  let(:test_class) { Struct.new(:util) { include Bulletproofs::Util } }
  let(:util) { test_class.new }

  describe "#delta" do
    it do
      json = JSON.parse(load_fixture("delta.json"))
      json.each do |t|
        if t["mod"]
          expect(util.delta(t["y"], t["z"], t["mod"])).to eq(t["result"])
        else
          expect(util.delta(t["y"], t["z"])).to eq(t["result"])
        end
      end
    end
  end
end
