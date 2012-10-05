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


class PasswdChangeLdapTest < Test::Unit::TestCase
  include Rack::Test::Methods
  
  # Tests for method: connection?
  def test_connection_not_available 
    ldap_settings= {:base=>"dc=test,dc=test", :host=>"ldapi.example.com", :encryption=>:simple_tls, :port=>"636"}
    pwcldap = PasswdChangeLdap.new(ldap_settings)
    assert_equal false, pwcldap.connection?
  end

  def test_connection_available
    mock_ldap
    MockLdap.any_instance.expects(:bind).raises(Net::LDAP::LdapError, "no connection to server")
    pwcldap = new_pwcldap_example
    assert_equal false, pwcldap.connection?
  end

  # Tests for method: fetch_user_dn(username, password)
  def test_should_return_user_dn_mocked
    mock_ldap
    result_entry = passwdtest_ldap
    MockLdap.any_instance.expects(:bind_as).with(
        :base => 'dc=example,dc=itc',
        :filter => 'uid=passwdtest',
        :password => 'test4321'
      ).returns([result_entry])
    result_entry.expects(:dn).returns(passwdtest_ldap[:dn].to_s)
    pwcldap = new_pwcldap_example
    assert_equal "uid=passwdtest,ou=users,dc=example,dc=com", pwcldap.fetch_user_dn("passwdtest", 'test4321')
  end

  def test_should_raise_error_with_invalid_credentials
    mock_ldap
    MockLdap.any_instance.expects(:bind_as).twice.with(
      :base     => example_config[:base],
      :filter   => "uid=invaliduser",
      :password => "invalid" ).returns(false)
    pwcldap = new_pwcldap_example
    assert_raise_message(RuntimeError, /Wrong username or password/ ) {pwcldap.fetch_user_dn("invaliduser", "invalid")}
    assert_raise_message(RuntimeError, /Wrong username or password/ ) {pwcldap.authenticate("invaliduser", "invalid")}
  end

  # Tests for method: connect(user_dn=nil, password=nil)
  def test_should_connect_with_valid_credentials
    user_dn = "uid=passwdtest,ou=users,dc=example,dc=com"
    ldap = mock()
    Net::LDAP.expects(:new).with(example_config)
    Net::LDAP.expects(:new).with(example_config.merge(
      :auth => { :method => :simple,
                 :username => user_dn,
                 :password => 'test4321'})
      ).returns(ldap)
     ldap.expects(:bind).returns(true)
   pwcldap = new_pwcldap_example
   assert pwcldap.connect("uid=passwdtest,ou=users,dc=example,dc=com", 'test4321')
  end
 
  # Tests for method: authenticate(username, password)
  def test_should_authenticate_with_valid_credentials
    user_dn = "uid=passwdtest,ou=users,dc=example,dc=com"
    ldap = mock()
    Net::LDAP.expects(:new).with(example_config)
    Net::LDAP.expects(:new).with(example_config.merge(
      :auth => { :method => :simple,
                 :username => user_dn,
                 :password => 'test4321'})
      ).returns(ldap)
     ldap.expects(:bind).returns(true)
   pwcldap = new_pwcldap_example
   pwcldap.expects(:fetch_user_dn).with("passwdtest", 'test4321').returns(user_dn)
   assert pwcldap.authenticate("passwdtest", 'test4321')
  end

  # Tests for method change_password(username, password, newpassword)
  def test_change_password
    user_dn = "uid=passwdtest,ou=users,dc=example,dc=com"
    user_oldpw = 'test4321'
    user_newpw = "newpassword1234"
    pwcldap = new_pwcldap_example
    pwcldap.expects(:fetch_user_dn).with("passwdtest", user_oldpw).returns(user_dn)
    # pwcldap.expects(:connect).with(user_dn, user_oldpw).returns(true)
    mock_ldap()
    result1=mock()
    result1.stubs(:code).returns(0)
    @ldap.stubs(:get_operation_result).returns(result1)
    @ldap.stubs(:bind).returns(true)
    @ldap.expects(:replace_attribute).with(user_dn, "sambaNTPassword",'5B0F9AA2FC5FACF786D1E60F6DF1CAB0').returns(true)
    @ldap.expects(:replace_attribute).with(user_dn, "userPassword", regexp_matches(/^\{SSHA\}/)).returns(true)
    assert pwcldap.change_password("passwdtest", 'test4321', "newpassword1234")
  end

  def test_change_with_invalid_credentials
    mock_ldap()
    pwcldap = new_pwcldap_example
    pwcldap.expects(:fetch_user_dn).with("passwdtest", "wrongpw").returns(false)
    assert_raise_message(RuntimeError, "Invalid request, wrong password" ) { pwcldap.change_password("passwdtest", 'wrongpw', "newpassword1234")}
  end

  def test_change_failed
    user_dn = "uid=passwdtest,ou=users,dc=example,dc=com"
    user_oldpw = 'test4321'
    user_newpw = "newpassword1234"
    pwcldap = new_pwcldap_example
    pwcldap.expects(:fetch_user_dn).with("passwdtest", user_oldpw).returns(user_dn)
    mock_ldap()
    result1=mock()
    result1.stubs(:code).returns(1)
    @ldap.stubs(:get_operation_result).returns(result1)
    @ldap.stubs(:bind).returns(true)
    @ldap.expects(:replace_attribute).with(user_dn, "sambaNTPassword",'5B0F9AA2FC5FACF786D1E60F6DF1CAB0').returns(true)
    @ldap.expects(:replace_attribute).with(user_dn, "sambaNTPassword", '9F699D92689E51641866F45D71553987').returns(true) #reset
    @ldap.expects(:replace_attribute).with(user_dn, "userPassword", regexp_matches(/^\{SSHA\}/)).returns(true) #reset
    assert_raise_message(RuntimeError, "Error changing password, password reset" ) {pwcldap.change_password("passwdtest", 'test4321', "newpassword1234")}
  end

  def test_change_failed_server_not_authorized
    user_dn = "uid=passwdtest,ou=users,dc=example,dc=com"
    user_oldpw = 'test4321'
    user_newpw = "newpassword1234"
    pwcldap = new_pwcldap_example
    pwcldap.expects(:fetch_user_dn).with("passwdtest", user_oldpw).returns(user_dn)
    # pwcldap.expects(:connect).with(user_dn, user_oldpw).returns(true)
    mock_ldap()
    result1=mock()
    result1.stubs(:code).returns(10)
    @ldap.stubs(:get_operation_result).returns(result1)
    @ldap.stubs(:bind).returns(true)
    @ldap.expects(:replace_attribute).with(user_dn, "sambaNTPassword",'5B0F9AA2FC5FACF786D1E60F6DF1CAB0').returns(true)
    assert_raise_message(RuntimeError, "Server not authorized" ) {pwcldap.change_password("passwdtest", 'test4321', "newpassword1234")}
  end


  private

  def app
    Sinatra::Application
  end

  def mock_ldap
    @ldap = MockLdap.new
    Net::LDAP.stubs(:new).returns(@ldap)
  end

  def nice_girl_ldap
    { :uid => ['ngirl'],:uidnumber => ['42'], :gidnumber => ['2'] }
  end

  def passwdtest_ldap
    {:homedirectory=>["/ldaphome/passwdtest"], :uid=>["passwdtest"], :loginshell=>["/bin/bash"], :sn=>["PasswdTest"], :uidnumber=>["10286"], :givenname=>["Philipp"], :dn=>["uid=passwdtest,ou=users,dc=example,dc=com"], :gidnumber=>["10019"], :cn=>["Philipp PasswdTest"], :objectclass=>["posixAccount", "inetOrgPerson", "organizationalPerson", "person"]}
  end

  def r
    last_response
  end
  
  def new_pwcldap_example
    PasswdChangeLdap.new(example_config)
  end

  def example_config
    {:host => 'example.ch',
      :port => 636,
      :base => 'dc=example,dc=itc',
      :encryption => :simple_tls,
    }
  end
  
  def config
    YAML.load_file('config.yml')
  end

  def assert_raise_message(types, matcher, message = nil, &block)
    args = [types].flatten + [message]
    exception = assert_raise(*args, &block)
    assert_match matcher, exception.message, message
  end
end

class MockLdap
  #dummy class
end
