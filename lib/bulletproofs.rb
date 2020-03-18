require "bulletproofs/version"
require 'matrix'

module Bulletproofs
  class Error < StandardError; end

  autoload :InnerProduct, 'bulletproofs/inner_product'

end
