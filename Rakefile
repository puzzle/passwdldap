require 'rubygems'
require 'bundler'

Bundler.setup(:default, :development)

require 'rake/testtask'

task :default => :test
 
desc "Run the tests."
Rake::TestTask.new do |t|
  t.libs << "tests"
  t.test_files = FileList['tests/*test.rb']
  t.verbose = true
end
