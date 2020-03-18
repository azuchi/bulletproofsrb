require "bulletproofs/version"
require 'matrix'

module Bulletproofs
  class Error < StandardError; end

  autoload :InnerProduct, 'bulletproofs/inner_product'

end

class Integer

  # Calculate population count this value.
  # @return [Integer] population count
  def popcount
    self.to_s(2).count('1')
  end

end