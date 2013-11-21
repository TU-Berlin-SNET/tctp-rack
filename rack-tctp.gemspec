Gem::Specification.new do |s|
  s.name        = 'rack-tctp'
  s.version     = '0.9.0'
  s.date        = '2013-11-21'
  s.summary     = 'Rack TCTP middleware'
  s.description = 'Rack middleware for end-to-end security through TCTP'
  s.authors     = ['Mathias Slawik']
  s.email       = 'mathias.slawik@tu-berlin.de'
  s.files       = %w[lib/rack-tctp.rb lib/rack/tctp.rb lib/rack/tctp/halec.rb]
  s.homepage    = 'https://github.com/mathiasslawik/rack-tctp'
  s.license     = 'Apache-2.0'
end