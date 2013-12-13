Gem::Specification.new do |s|
  s.name        = 'sakide'
  s.version     = '0.0.1'
  s.date        = '2013-12-13'
  s.summary     = "SAKIDE"
  s.description = "SAKIDE encryption modul for CIB bank credit card payments"
  s.authors     = ["Matyas Juhasz"]
  s.email       = 'juhasz.matyas@pixelface.hu'
  s.files       = ["lib/sakide.rb"]
  s.homepage    = 'http://rubygems.org/gems/sakide'
  s.license     = 'MIT'
  s.add_runtime_dependency "ruby-mcrypt"
end