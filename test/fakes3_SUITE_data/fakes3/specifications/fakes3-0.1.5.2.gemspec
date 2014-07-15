# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = "fakes3"
  s.version = "0.1.5.2"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Curtis Spencer"]
  s.date = "2013-10-21"
  s.description = "Use FakeS3 to test basic S3 functionality without actually connecting to S3"
  s.email = ["thorin@gmail.com"]
  s.executables = ["fakes3"]
  s.files = ["bin/fakes3"]
  s.homepage = ""
  s.require_paths = ["lib"]
  s.rubyforge_project = "fakes3"
  s.rubygems_version = "2.0.14"
  s.summary = "FakeS3 is a server that simulates S3 commands so you can test your S3 functionality in your projects"

  if s.respond_to? :specification_version then
    s.specification_version = 4

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_development_dependency(%q<bundler>, [">= 1.0.0"])
      s.add_development_dependency(%q<aws-s3>, [">= 0"])
      s.add_development_dependency(%q<right_aws>, [">= 0"])
      s.add_development_dependency(%q<rake>, [">= 0"])
      s.add_runtime_dependency(%q<thor>, [">= 0"])
      s.add_runtime_dependency(%q<builder>, [">= 0"])
    else
      s.add_dependency(%q<bundler>, [">= 1.0.0"])
      s.add_dependency(%q<aws-s3>, [">= 0"])
      s.add_dependency(%q<right_aws>, [">= 0"])
      s.add_dependency(%q<rake>, [">= 0"])
      s.add_dependency(%q<thor>, [">= 0"])
      s.add_dependency(%q<builder>, [">= 0"])
    end
  else
    s.add_dependency(%q<bundler>, [">= 1.0.0"])
    s.add_dependency(%q<aws-s3>, [">= 0"])
    s.add_dependency(%q<right_aws>, [">= 0"])
    s.add_dependency(%q<rake>, [">= 0"])
    s.add_dependency(%q<thor>, [">= 0"])
    s.add_dependency(%q<builder>, [">= 0"])
  end
end
