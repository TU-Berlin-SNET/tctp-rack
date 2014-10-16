# coding: utf-8
lib = File.expand_path('lib', __dir__)
$:.unshift(lib) unless $:.include?(lib)

require 'rack-tctp/version'

Gem::Specification.new do |s|
  s.name        = 'rack-tctp'
  s.version     = Rack::TCTP::VERSION
  s.date        = '2013-11-26'
  s.summary     = 'Rack TCTP middleware'
  s.description = 'Rack middleware for end-to-end security through TCTP'
  s.authors     = ['Mathias Slawik']
  s.email       = 'mathias.slawik@tu-berlin.de'
  s.files       = %w[lib/rack-tctp.rb lib/rack/tctp.rb lib/rack/tctp/halec.rb ext/engine/engine.c ext/engine/extconf.rb]
  s.homepage    = 'https://github.com/mathiasslawik/rack-tctp'
  s.license     = 'Apache-2.0'
  s.extensions = ['ext/engine/extconf.rb']
  
  s.add_development_dependency 'faker', '~> 1.1.2'
  s.add_development_dependency 'rack-test', '~> 0.6.2'
  s.add_development_dependency 'test-unit', '~> 2.5.5'
  s.add_development_dependency 'ruby-prof', '~> 0.13.0'
  s.add_development_dependency 'rake-compiler', '~> 0.9'

  s.add_runtime_dependency 'rest-client', '~> 1.6.7'
  s.add_runtime_dependency 'radix', '~> 2.2.0'
end
