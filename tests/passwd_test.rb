#!/usr/bin/env ruby
#  | # COPYRIGHT HEADER START # 
# |   PasswdLDAP is a Sinatra App that allows users to change their OpenLDAP Password
# |   Copyright (C) 2012 Puzzle ITC GmbH www.puzzle.ch
# |   
# |   This program is free software: you can redistribute it and/or modify
# |   it under the terms of the GNU Affero General Public License as
# |   published by the Free Software Foundation, either version 3 of the
# |   License, or (at your option) any later version.
# |   
# |   This program is distributed in the hope that it will be useful,
# |   but WITHOUT ANY WARRANTY; without even the implied warranty of
# |   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# |   GNU Affero General Public License for more details.
# |   
# |   You should have received a copy of the GNU Affero General Public License
# |   along with this program.  If not, see <http://www.gnu.org/licenses/>.
# | # COPYRIGHT HEADER END # 
 


require 'test_helper'

class PasswdTest < Test::Unit::TestCase
  include Rack::Test::Methods
  
  def test_index
    pwcldap = mock()
    PasswdChangeLdap.expects(:new).with(configuration['ldap_settings']).returns(pwcldap)
    pwcldap.expects(:connection?).returns(true)
    get '/'
    assert r.body.include?('Username')
    assert r.body.include?('Password')
    assert_equal 200, r.status
  end

  def test_no_connection
    pwcldap = mock()
    PasswdChangeLdap.expects(:new).times(3).with(configuration['ldap_settings']).returns(pwcldap)
    pwcldap.expects(:connection?).times(3).returns(false)
    get '/'
    assert r.body.include?('No connection to LDAP-Server')
    get '/change'
    assert r.body.include?('No connection to LDAP-Server')
    post '/change'
    assert r.body.include?('No connection to LDAP-Server')
  end

  def test_404
    mock_pwcldap
    get 'somepagethatdoesntexist'
    assert_equal 404, r.status
    assert r.body.include?("Page not found")
  end

  def test_valid_credentials
    mock_pwcldap
    get "/"
    MockPasswdChangeLdap.any_instance.expects(:authenticate).with("ngirl", "benice").returns(true)
    post "/", :username => "ngirl", :password => "benice", :captcha => "correct"
    follow_redirect!
    assert_equal "http://example.org/change", last_request.url
    assert_equal 200, r.status
    assert r.body.include?("Repeat new password")
  end

  def test_wrong_credentials
    mock_pwcldap
    get "/"
    MockPasswdChangeLdap.any_instance.expects(:authenticate).with("ngirl", "nonice").raises("Wrong username or password")
    post "/", :username => "ngirl", :password => "nonice", :captcha => "correct"
    follow_redirect!
    assert_equal "http://example.org/", last_request.url
    assert_equal 200, last_response.status
    assert last_response.body.include?("Enter your current credentials:"), "Wrong page rendered"
    assert last_response.body.include?("Wrong username or password"), "Missing flash"
  end
  def test_no_username
    mock_pwcldap
    post "/", :username => "", :password => "benice"
    follow_redirect!
    assert_equal "http://example.org/", last_request.url
    assert_equal 200, last_response.status
    assert last_response.ok?
    assert r.body.include?("Username not set")
  end

  def test_new_password_not_identical
    mock_pwcldap
    login_session
    post "/change", :newpassword1 => "benice42", :newpassword2 => "benice42withmistake"
    follow_redirect!
    assert_equal "http://example.org/change", last_request.url
    assert r.body.include?("Repeat new password"), "Wrong page rendered"
    assert r.body.include?("Passwords not identical"), "Miss flash notice 'Passwords not identical'"
  end

  def test_new_password_empty
    mock_pwcldap
    login_session
    post "/change", :newpassword1 => "", :newpassword2 => ""
    follow_redirect!
    assert_equal "http://example.org/change", last_request.url
    assert r.body.include?("Repeat new password"), "Wrong page rendered"
    assert r.body.include?('New Passwords too short (min. 8 chars required)'), "Miss flash notice 'New Passwords too short'"
  end

  def test_new_password_unsafe
    mock_pwcldap
    login_session
    post "/change", :newpassword1 => "a", :newpassword2 => "a"
    follow_redirect!
    assert_equal "http://example.org/change", last_request.url
    assert r.body.include?("Repeat new password"), "Wrong page rendered"
    assert r.body.include?('New Passwords too short (min. 8 chars required)'), "Miss flash notice 'New Passwords too short'"
  end

  def test_server_not_authoritative
    mock_pwcldap
    login_session
    MockPasswdChangeLdap.any_instance.expects(:change_password).with("ngirl", "benice", "newsecurepassword123456789" ).raises("Server not authorized")
    post "/change", :newpassword1 => "newsecurepassword123456789", :newpassword2 => "newsecurepassword123456789"
    follow_redirect!
    assert_equal "http://example.org/", last_request.url
    assert r.body.include?("Server not authorized"), "Miss flash notice 'Server not authorized'"
  end

  def test_wrong_captcha
    get "/"
    post "/", :username => "ngirl", :password => "benice", :captcha => "wrong"
    follow_redirect!
    assert_equal "http://example.org/", last_request.url
    assert_equal 200, r.status
    assert r.body.include?("captcha not valid"), "Miss flash notice 'captcha not valid'"
  end

  def test_change_successful
    mock_pwcldap
    login_session
    MockPasswdChangeLdap.any_instance.expects(:change_password).with("ngirl", "benice", "newsecurepassword123456789" ).returns(true)
    post "/change", :newpassword1 => "newsecurepassword123456789", :newpassword2 => "newsecurepassword123456789"
    follow_redirect!
    assert_equal "http://example.org/done", last_request.url
    assert r.body.include?("Password changed successfully"), "Miss text 'Password changed successfully'"
  end

  private

  def app
    PasswdApp
  end

  def mock_ldap
    Net::LDAP.stubs(:new).returns(MockLdap.new)
  end

  def nice_girl_ldap
    { :uid => ['ngirl'],:uidnumber => ['42'], :gidnumber => ['2'] }
  end

  def r
    last_response
  end

  def configuration
    YAML.load_file('config.yml')
  end

  def mock_pwcldap
    PasswdChangeLdap.stubs(:new).returns(MockPasswdChangeLdap.new)
  end

  def login_session
    post "/", :username => "ngirl", :password => "benice", :captcha => "correct" # init session
  end

  def debug_page(content=last_response.body, file='/tmp/sinatra_debug.htm')
    File.open(file, 'w') do |f|
       f.puts content
    end
  end
end



class MockPasswdChangeLdap
  def connection?
    true
  end
  #dummy class
end
