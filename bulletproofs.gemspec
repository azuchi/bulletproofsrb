# frozen_string_literal: true

require_relative 'lib/bulletproofs/version'

Gem::Specification.new do |spec|
  spec.name          = 'bulletproofs'
  spec.version       = Bulletproofs::VERSION
  spec.authors       = ['azuchi']
  spec.email         = ['azuchi@chaintope.com']

  spec.summary       = 'A ruby implementation of Bulletproofs.'
  spec.description   = 'A ruby implementation of Bulletproofs.'
  spec.homepage      = 'https://github.com/azuchi/bulletproofsrb'
  spec.license       = 'MIT'
  spec.required_ruby_version = Gem::Requirement.new('>= 2.7.0')

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files         = Dir.chdir(File.expand_path(__dir__)) do
    `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  end
  spec.bindir        = 'exe'
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ['lib']

  spec.add_runtime_dependency 'ecdsa_ext', '>= 0.3.2'

  spec.add_development_dependency 'bundler'
  spec.add_development_dependency 'rake', '>= 12.3.3'
  spec.add_development_dependency 'rspec', '~> 3.0'
end
